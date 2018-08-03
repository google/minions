# Minions roadmap

In general, we want the project to take off quickly by providing something that can be run cheapily and immediately delivers value.

The basic workflow we'll be targeting first are the Cloud native ones, with a very low barrier for entry in terms of setup.

Once we hit Version 0.4 we'll likely do some large-scale testing on public repositories of images (always a PR hit) and start advertising the software. We'll see what happens after that.

## Version 0.1

First working version of Minions with the basic e2e workflow.

- [x] Local goblin with local FS access.
- [ ] Full Overlord implementation (data chunks reassembly,
      routing to Minions)
- [ ] 3 Minions, of which at least 1 with state keeping.
- [ ] Minions and Overlord have clear runners
- [ ] Clear step by step "how to run it" instructions.

## Version 0.2

"I can actually run this over a network"

- [ ] The entire workflow uses TLS for
      basic authentication and confidentiality over gRPC.
- [ ] Step by step guide to set up the certificate madness.

## Version 0.3

"I can run this in prod"

Goblins support use cases people actually have. Things like Spinnaker integration, access to VMs in cloud providers and so on.

## Version 0.4

"I can run it every day"

Caching layers and optimizations make it cheap to keep running the scans against the same set of targets on a regular basis.
