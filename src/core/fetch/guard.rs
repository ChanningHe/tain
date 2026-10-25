//! Redirect policy: no https→http downgrade, no hop into loopback/private/
//! link-local space unless the origin itself lives there.
//!
//! Only literal targets (IP addresses, localhost aliases) are judged: a DNS
//! name that resolves to an internal address is NOT blocked. Deployments that
//! need egress isolation should enforce it outside tain (systemd
//! `IPAddressDeny=`, container network policy).
//!
//! "Internal origin" is judged literally too: a mirror URL with a hostname
//! (even one resolving into the LAN) that redirects to an internal IP literal
//! is refused. A LAN redirector that does that needs the mirror URL written
//! with its internal IP literal.

use std::net::{IpAddr, Ipv4Addr};

use url::Url;

pub(super) const MAX_REDIRECTS: usize = 10;

/// Follow at most [`MAX_REDIRECTS`] hops, never downgrading https→http and
/// never to an internal literal unless the request's origin is internal too
/// (a LAN mirror may redirect within the LAN).
pub(super) fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        match redirect_refusal(attempt.previous(), attempt.url()) {
            Some(why) => attempt.error(why),
            None => attempt.follow(),
        }
    })
}

/// Why the hop from `previous` (oldest first) to `next` is refused, if it is.
fn redirect_refusal(previous: &[Url], next: &Url) -> Option<String> {
    if previous.len() > MAX_REDIRECTS {
        return Some(format!("more than {MAX_REDIRECTS} redirects"));
    }
    if !matches!(next.scheme(), "http" | "https") {
        return Some(format!(
            "redirect to unsupported scheme `{}`",
            next.scheme()
        ));
    }
    if next.scheme() == "http" && previous.iter().any(|u| u.scheme() == "https") {
        return Some(format!("redirect downgrades https to {next}"));
    }
    let origin_internal = previous.first().is_some_and(is_internal_host);
    if is_internal_host(next) && !origin_internal {
        return Some(format!("redirect into a local/private address: {next}"));
    }
    None
}

fn is_internal_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => is_internal_ip(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => is_internal_ip(IpAddr::V6(ip)),
        Some(url::Host::Domain(d)) => is_internal_name(d),
        None => true,
    }
}

/// Loopback aliases that common `/etc/hosts` files define.
fn is_internal_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    name.ends_with(".localhost")
        || matches!(
            name.as_str(),
            "localhost"
                | "localhost.localdomain"
                | "localhost6"
                | "localhost6.localdomain6"
                | "ip6-localhost"
                | "ip6-loopback"
        )
}

/// Any address that is not plain public unicast.
fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // ::a.b.c.d (IPv4-compatible) and ::ffff:a.b.c.d (mapped).
            if let Some(v4) = v6.to_ipv4() {
                return is_internal_v4(v4);
            }
            // Well-known NAT64 prefix 64:ff9b::/96 reaches the IPv4 address in
            // the last 32 bits. Other RFC 6052 layouts (e.g. local-use
            // 64:ff9b:1::/48) place it elsewhere and are treated as plain IPv6.
            if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [.., hi, lo] = seg;
                return is_internal_v4(Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo)));
            }
            let first = seg[0];
            v6.is_multicast()
                // fc00::/7 unique-local.
                || (first & 0xFE00) == 0xFC00
                // fe80::/10 link-local, fec0::/10 deprecated site-local.
                || (first & 0xFFC0) == 0xFE80
                || (first & 0xFFC0) == 0xFEC0
        }
    }
}

fn is_internal_v4(v4: Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    a == 0 // 0.0.0.0/8 "this network"
        || v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_multicast()
        || a >= 240 // 240.0.0.0/4 reserved, incl. broadcast
        || (a == 100 && (b & 0xC0) == 64) // 100.64.0.0/10 CGNAT
        || (a == 198 && (b & 0xFE) == 18) // 198.18.0.0/15 benchmarking
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn redirect_to_public_https_is_followed() {
        assert_eq!(
            redirect_refusal(
                &[u("https://deb.debian.org/x")],
                &u("https://cdn.example.net/x")
            ),
            None
        );
        assert_eq!(
            redirect_refusal(&[u("http://a.example/x")], &u("https://b.example/x")),
            None
        );
    }

    #[test]
    fn redirect_https_to_http_is_refused() {
        let why = redirect_refusal(&[u("https://a.example/x")], &u("http://a.example/x"));
        assert!(why.unwrap().contains("downgrade"));
        // Anywhere in the chain.
        let chain = [u("https://a.example/x"), u("https://b.example/x")];
        assert!(redirect_refusal(&chain, &u("http://c.example/x")).is_some());
    }

    #[test]
    fn redirect_into_internal_space_is_refused_from_public_origin() {
        let origin = [u("http://mirror.example/debian/x")];
        for target in [
            "http://127.0.0.1/x",
            "http://localhost:8080/x",
            "http://localhost.localdomain/x",
            "http://ip6-localhost/x",
            "http://ip6-loopback/x",
            "http://10.1.2.3/x",
            "http://172.16.0.1/x",
            "http://192.168.1.1/x",
            "http://169.254.169.254/latest/meta-data",
            "http://0.0.0.0/x",
            "http://0.1.2.3/x",
            "http://100.64.0.1/x",
            "http://198.18.0.1/x",
            "http://224.0.0.1/x",
            "http://240.0.0.1/x",
            "http://255.255.255.255/x",
            "http://[::1]/x",
            "http://[::]/x",
            "http://[fe80::1]/x",
            "http://[fec0::1]/x",
            "http://[fd00::1]/x",
            "http://[ff02::1]/x",
            "http://[::ffff:127.0.0.1]/x",
            "http://[::7f00:1]/x",
            "http://[64:ff9b::a9fe:a9fe]/x",
            "http://localhost./x",
            "http://LOCALHOST.LOCALDOMAIN./x",
            "http://ip6-loopback./x",
        ] {
            assert!(
                redirect_refusal(&origin, &u(target)).is_some(),
                "{target} must be refused"
            );
        }
    }

    #[test]
    fn public_addresses_are_not_internal() {
        for ip in [
            "1.1.1.1",
            "151.101.2.132",
            "2a04:4e42::644",
            "64:ff9b::808:808",
            "64:ff9b:1::808:808",
            // Local-use NAT64 layout is plain IPv6, whatever it embeds.
            "64:ff9b:1::a00:1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_internal_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn redirect_within_internal_space_is_allowed_for_internal_origin() {
        assert_eq!(
            redirect_refusal(&[u("http://10.0.0.5/debian/x")], &u("http://10.0.0.6/x")),
            None
        );
        assert_eq!(
            redirect_refusal(
                &[u("http://127.0.0.1:8080/x")],
                &u("http://127.0.0.1:9090/x")
            ),
            None
        );
    }

    #[test]
    fn redirect_hops_and_schemes_are_capped() {
        let chain: Vec<Url> = (0..=MAX_REDIRECTS)
            .map(|i| u(&format!("http://h{i}.example/")))
            .collect();
        assert!(redirect_refusal(&chain, &u("http://next.example/")).is_some());
        assert!(redirect_refusal(&chain[..MAX_REDIRECTS], &u("http://next.example/")).is_none());
        assert!(redirect_refusal(&chain[..1], &u("file:///etc/passwd")).is_some());
    }
}
