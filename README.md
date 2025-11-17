# BGPnet

Small BGP lab environment built around:

- `libbgp/`: vendored copy of the libbgp library (C++).
- `bgp-scenarios/`: mini BGP node, RouteViews scenarios, and Ansible deployment.

## Structure

- `libbgp/`: third-party library (built with autotools).
- `bgp-scenarios/mini-node/`: `bgp_node.cpp` and compiled `bgp_node` binary.
- `bgp-scenarios/scenarios/raw/`: raw RouteViews text dumps.
- `bgp-scenarios/scenarios/generated/`: per-AS `.scenario` files.
- `bgp-scenarios/ansible/`: Ansible playbook to run a small distributed BGP experiment.
- `bgp-scenarios/runtime/`: runtime directory (created/overwritten by Ansible).

## Quick start

```bash
cd bgp-scenarios

# build mini-node (requires libbgp installed system-wide or built from ../libbgp)
cd mini-node
g++ -std=c++11 bgp_node.cpp \
    -I/usr/local/include \
    -L/usr/local/lib -lbgp -lpthread \
    -o bgp_node
cd ..

# regenerate scenarios from a raw RouteViews file (already provided)
scenarios/scripts/make_bgp_scenarios.sh \
  scenarios/raw/rv2_20230101_1h_raw.txt \
  rv2_20230101_1h

# run the 2-node lab with Ansible
cd ansible
ansible-playbook -i inventories/lab/hosts.ini deploy.yml

