use rsip::{headers::ToTypedHeader, prelude::HeadersExt};
use rsipstack::{
    rsip_ext::RsipResponseExt, transaction::endpoint::MessageInspector, transport::SipAddr,
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearnedPublicAddress {
    pub transport: rsip::Transport,
    pub host_with_port: rsip::HostWithPort,
}

#[derive(Clone, Default)]
pub struct LearnedPublicAddresses {
    inner: Arc<RwLock<HashMap<rsip::Transport, rsip::HostWithPort>>>,
}

impl LearnedPublicAddresses {
    pub fn store(
        &self,
        transport: Option<&rsip::Transport>,
        host_with_port: rsip::HostWithPort,
    ) -> bool {
        let transport = normalize_transport(transport);
        let mut guard = self.inner.write().unwrap();
        if guard.get(&transport) == Some(&host_with_port) {
            return false;
        }
        guard.insert(transport, host_with_port);
        true
    }

    pub fn get(&self, transport: Option<&rsip::Transport>) -> Option<rsip::HostWithPort> {
        let transport = normalize_transport(transport);
        self.inner.read().unwrap().get(&transport).cloned()
    }

    pub fn learn_from_response(&self, response: &rsip::Response) -> Option<LearnedPublicAddress> {
        let host_with_port = response.via_received()?;
        let transport = response
            .via_header()
            .ok()
            .and_then(|via| via.typed().ok())
            .map(|via| via.transport)
            .unwrap_or(rsip::Transport::Udp);
        self.store(Some(&transport), host_with_port.clone());
        Some(LearnedPublicAddress {
            transport,
            host_with_port,
        })
    }
}

pub fn normalize_transport(transport: Option<&rsip::Transport>) -> rsip::Transport {
    transport.cloned().unwrap_or(rsip::Transport::Udp)
}

pub fn transport_for_uri(uri: &rsip::Uri) -> rsip::Transport {
    if matches!(uri.scheme, Some(rsip::Scheme::Sips)) {
        return rsip::Transport::Tls;
    }

    uri.params
        .iter()
        .find_map(|param| match param {
            rsip::Param::Transport(transport) => Some(transport.clone()),
            _ => None,
        })
        .unwrap_or(rsip::Transport::Udp)
}

pub fn contact_needs_public_resolution(contact: &rsip::Uri) -> bool {
    if contact.scheme.is_none() {
        return true;
    }

    match &contact.host_with_port.host {
        rsip::Host::Domain(domain) => {
            let host = domain.to_string();
            host.eq_ignore_ascii_case("localhost")
        }
        rsip::Host::IpAddr(ip) => is_local_or_unspecified(ip),
    }
}

pub fn build_contact_uri(
    local_addr: &SipAddr,
    learned_addr: Option<rsip::HostWithPort>,
    username: Option<&str>,
    template: Option<&rsip::Uri>,
) -> rsip::Uri {
    let mut uri = template
        .cloned()
        .unwrap_or_else(|| rsip::Uri::from(local_addr));

    uri.host_with_port = learned_addr.unwrap_or_else(|| local_addr.addr.clone());
    if uri.scheme.is_none() {
        uri.scheme = Some(match local_addr.r#type {
            Some(rsip::Transport::Tls)
            | Some(rsip::Transport::Wss)
            | Some(rsip::Transport::TlsSctp) => rsip::Scheme::Sips,
            _ => rsip::Scheme::Sip,
        });
    }

    if uri.auth.is_none() {
        if let Some(username) = username.filter(|value| !value.is_empty()) {
            uri.auth = Some(rsip::Auth {
                user: username.to_string(),
                password: None,
            });
        }
    }

    uri
}

pub fn build_public_contact_uri(
    learned_public_addresses: &LearnedPublicAddresses,
    auto_learn_public_address: bool,
    local_addr: &SipAddr,
    username: Option<&str>,
    template: Option<&rsip::Uri>,
) -> rsip::Uri {
    let learned_addr = if auto_learn_public_address {
        learned_public_addresses.get(local_addr.r#type.as_ref())
    } else {
        None
    };
    build_contact_uri(local_addr, learned_addr, username, template)
}

pub struct LearningMessageInspector {
    learned_public_addresses: LearnedPublicAddresses,
    next: Option<Box<dyn MessageInspector>>,
}

impl LearningMessageInspector {
    pub fn new(
        learned_public_addresses: LearnedPublicAddresses,
        next: Option<Box<dyn MessageInspector>>,
    ) -> Self {
        Self {
            learned_public_addresses,
            next,
        }
    }
}

impl MessageInspector for LearningMessageInspector {
    fn before_send(&self, msg: rsip::SipMessage, dest: Option<&SipAddr>) -> rsip::SipMessage {
        if let Some(next) = &self.next {
            next.before_send(msg, dest)
        } else {
            msg
        }
    }

    fn after_received(&self, msg: rsip::SipMessage, from: &SipAddr) -> rsip::SipMessage {
        let msg = if let Some(next) = &self.next {
            next.after_received(msg, from)
        } else {
            msg
        };

        if let rsip::SipMessage::Response(response) = &msg {
            self.learned_public_addresses.learn_from_response(response);
        }

        msg
    }
}

fn is_local_or_unspecified(ip: &IpAddr) -> bool {
    ip.is_loopback() || ip.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::{
        LearnedPublicAddresses, build_contact_uri, build_public_contact_uri,
        contact_needs_public_resolution, transport_for_uri,
    };
    use rsip::transport::Transport;
    use rsipstack::transport::SipAddr;

    #[test]
    fn learns_public_address_from_response_via() {
        let cache = LearnedPublicAddresses::default();
        let response: rsip::Response = concat!(
            "SIP/2.0 401 Unauthorized\r\n",
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-1;received=203.0.113.10;rport=62000\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        )
        .try_into()
        .unwrap();

        let learned = cache.learn_from_response(&response).unwrap();
        assert_eq!(learned.transport, Transport::Udp);
        assert_eq!(learned.host_with_port.to_string(), "203.0.113.10:62000");
        assert_eq!(
            cache.get(Some(&Transport::Udp)).unwrap().to_string(),
            "203.0.113.10:62000"
        );
    }

    #[test]
    fn builds_contact_using_learned_public_address() {
        let local_addr = SipAddr {
            r#type: Some(Transport::Udp),
            addr: "10.0.0.5:5060"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        };
        let template: rsip::Uri = "sip:alice@127.0.0.1:5060".try_into().unwrap();
        let learned_addr = Some(
            "203.0.113.10:62000"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        );

        let contact = build_contact_uri(&local_addr, learned_addr, Some("alice"), Some(&template));
        assert_eq!(contact.to_string(), "sip:alice@203.0.113.10:62000");
    }

    #[test]
    fn identifies_contacts_that_need_resolution() {
        let local_contact: rsip::Uri = "sip:alice@127.0.0.1:5060".try_into().unwrap();
        let remote_contact: rsip::Uri = "sip:alice@203.0.113.10:62000".try_into().unwrap();
        assert!(contact_needs_public_resolution(&local_contact));
        assert!(!contact_needs_public_resolution(&remote_contact));
    }

    #[test]
    fn builds_public_contact_from_shared_cache() {
        let cache = LearnedPublicAddresses::default();
        cache.store(
            Some(&Transport::Udp),
            "203.0.113.20:62000"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        );
        let local_addr = SipAddr {
            r#type: Some(Transport::Udp),
            addr: "10.0.0.5:5060"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        };

        let contact = build_public_contact_uri(&cache, true, &local_addr, Some("alice"), None);
        assert_eq!(contact.to_string(), "sip:alice@203.0.113.20:62000");
    }

    #[test]
    fn infers_transport_from_uri() {
        let sips_uri: rsip::Uri = "sips:alice@example.com".try_into().unwrap();
        let tcp_uri: rsip::Uri = "sip:alice@example.com;transport=tcp".try_into().unwrap();
        assert_eq!(transport_for_uri(&sips_uri), Transport::Tls);
        assert_eq!(transport_for_uri(&tcp_uri), Transport::Tcp);
    }
}
