//! Address-family-aware longest-prefix matching.

use crate::{address::ip::ipnet::IpNet, std::boxed::Box};
use core::net::IpAddr;

/// A binary prefix trie with separate IPv4 and IPv6 roots.
///
/// Lookup takes at most 32 or 128 bit steps, regardless of the number of routes.
/// Inserting an existing prefix replaces its value; host bits are normalized.
#[derive(Debug, Clone)]
pub struct IpPrefixMap<V> {
    v4: Node<V>,
    v6: Node<V>,
    len: usize,
}
#[derive(Debug, Clone)]
struct Node<V> {
    value: Option<(IpNet, V)>,
    children: [Option<Box<Self>>; 2],
}
impl<V> Default for Node<V> {
    fn default() -> Self {
        Self {
            value: None,
            children: [None, None],
        }
    }
}
impl<V> Default for IpPrefixMap<V> {
    fn default() -> Self {
        Self {
            v4: Node::default(),
            v6: Node::default(),
            len: 0,
        }
    }
}

impl<V> IpPrefixMap<V> {
    /// Creates an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Returns the number of stored prefixes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }
    /// Returns whether the map is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Inserts a prefix, returning the replaced value, if any.
    pub fn insert(&mut self, network: IpNet, value: V) -> Option<V> {
        let network = network.trunc();
        let (bits, width) = address_bits(network.addr());
        let mut node = if width == 32 {
            &mut self.v4
        } else {
            &mut self.v6
        };
        for shift in (width - u32::from(network.prefix_len())..width).rev() {
            node = node.children[((bits >> shift) & 1) as usize]
                .get_or_insert_with(|| Box::new(Node::default()));
        }
        let previous = node.value.replace((network, value));
        if previous.is_none() {
            self.len += 1;
        }
        previous.map(|(_, value)| value)
    }

    /// Returns the most specific matching network and its value.
    #[must_use]
    pub fn longest_match(&self, address: IpAddr) -> Option<(IpNet, &V)> {
        let (bits, width) = address_bits(address);
        let mut node = if width == 32 { &self.v4 } else { &self.v6 };
        let mut best = node.value.as_ref();
        for shift in (0..width).rev() {
            let Some(child) = node.children[((bits >> shift) & 1) as usize].as_deref() else {
                break;
            };
            node = child;
            if node.value.is_some() {
                best = node.value.as_ref();
            }
        }
        best.map(|(network, value)| (*network, value))
    }

    /// Removes an exact prefix. Broader routes remain available to lookup.
    pub fn remove(&mut self, network: IpNet) -> Option<V> {
        let (bits, width) = address_bits(network.addr());
        let root = if width == 32 {
            &mut self.v4
        } else {
            &mut self.v6
        };
        let result = remove(root, bits, width, u32::from(network.prefix_len()));
        if result.is_some() {
            self.len -= 1;
        }
        result
    }
}

fn address_bits(address: IpAddr) -> (u128, u32) {
    match address {
        IpAddr::V4(ip) => (u128::from(ip.to_bits()), 32),
        IpAddr::V6(ip) => (ip.to_bits(), 128),
    }
}
fn remove<V>(node: &mut Node<V>, bits: u128, width: u32, remaining: u32) -> Option<V> {
    if remaining == 0 {
        return node.value.take().map(|(_, value)| value);
    }
    let index = ((bits >> (width - 1)) & 1) as usize;
    let child = node.children[index].as_deref_mut()?;
    let value = remove(child, bits, width - 1, remaining - 1);
    if child.value.is_none() && child.children.iter().all(Option::is_none) {
        node.children[index] = None;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn longest_match_replacement_removal_and_family_separation() {
        let mut map = IpPrefixMap::new();
        map.insert("0.0.0.0/0".parse().unwrap(), "v4");
        map.insert("::/0".parse().unwrap(), "v6");
        map.insert("10.1.2.3/8".parse().unwrap(), "private");
        map.insert("10.1.0.0/16".parse().unwrap(), "subnet");
        map.insert("10.1.2.3/32".parse().unwrap(), "host");
        for (address, expected) in [
            ("10.1.2.3", "host"),
            ("10.1.2.4", "subnet"),
            ("10.2.0.1", "private"),
            ("192.0.2.1", "v4"),
            ("::ffff:10.1.2.3", "v6"),
        ] {
            assert_eq!(
                *map.longest_match(address.parse().unwrap()).unwrap().1,
                expected
            );
        }
        assert_eq!(
            map.insert("10.9.0.0/8".parse().unwrap(), "replaced"),
            Some("private")
        );
        assert_eq!(map.len(), 5);
        assert_eq!(map.remove("10.1.2.3/32".parse().unwrap()), Some("host"));
        assert_eq!(
            *map.longest_match("10.1.2.3".parse().unwrap()).unwrap().1,
            "subnet"
        );
        map.insert("2001:db8::1/128".parse().unwrap(), "v6-host");
        assert_eq!(
            *map.longest_match("2001:db8::1".parse().unwrap()).unwrap().1,
            "v6-host"
        );
        assert_eq!(
            map.remove("2001:db8::1/128".parse().unwrap()),
            Some("v6-host")
        );
    }
}
