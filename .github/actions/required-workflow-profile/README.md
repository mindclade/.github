# Required workflow profile action

Owner: @mindclade/developer-platform
Last reviewed: 2026-09-02
Review cadence: 180 days

This composite action resolves only repository identities declared in the generated profile
catalog. It never accepts commands, runner labels, workflow references, or permission sets from a
caller.

In `review` mode it requires either two current, distinct, non-author approvals or the durable
founder pull-request bypass protocol:

1. Apply the exact `founder-bypass` label.
2. One account in the digest-bound identity projection posts an exact three-line comment:

   ```text
   <!-- founder-pr-bypass:v1 -->
   head-sha: 0123456789abcdef0123456789abcdef01234567
   reason: A nonempty single-line reason of at most 500 characters
   ```

The SHA must equal the live pull-request head. A new commit therefore invalidates the evidence.
The action emits canonical evidence but grants no GitHub bypass, environment approval, or
privileged execution authority. The stable CI check and every separately configured ruleset remain
mandatory.
