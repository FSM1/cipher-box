# Session Context

## User Prompts

### Prompt 1

some very valid points raised by coderabbit on the pr. Please make sure the docs are consistent. full schema should not be updated ever, it is a point in time snapshot.

### Prompt 2

yes please, and comment on all coderabbit issues please.

### Prompt 3

ok, I wanted to strategize for a couple of minutes regarding the context note for phase 14, regarding the tradeoff made between centralized database vs metadata based sharing. One thing I was thinking of is share discovery, but I had am idea I wanted to validate with you. if we use a IPNS private key that is HKDF of the receiving persons public key, this could be a way to trustlessly grant someone access to a file/folder. Basically the ipns could point at a sort of `inbox` of share invitations w...

### Prompt 4

I am honestly just playing with ideas in my head and trying to keep this as "serverless" as possible. I get that our biggest issue is IPNS flakiness, and feel that since we seem to be getting a bunch of `write conflict complexity` type issues in a whole host of operations, it will be easier to focus on finding creative ways to solve the ipns issues since the problems are all the same basically.

### Prompt 5

I like the CRDT idea and generally you described my nonsense really eloquently. Can we document this whole discussion somewhere in the planning, I think there is already a todo to investigate alternatives to delegated-ipfs.dev so maybe another research oriented todo could be in order.

