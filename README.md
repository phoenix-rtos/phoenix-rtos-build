# phoenix-rtos-build
Phoenix-RTOS building scripts

Scripts in this repository should be called from the project root directory (phoenix-rtos-project). For description of the building process please see [docs.phoenix-rtos.com/building](https://docs.phoenix-rtos.com/latest/building/index.html).

Additional description provided in this README is related to the generation of function call graphs.

## Generate graphs

### Prerequisites

    Python 3
    Graphviz
    GRAPHS=1 (Enables the generation of .expand files.)
Download the graph generation script:
```
wget -P phoenix-rtos-build/scripts https://raw.githubusercontent.com/chaudron/cally/refs/heads/master/cally.py
```
Note: Set NOCHECKENV=1 to run the command without checking for the full toolchain.

### Usage

Run the commands from the project root.
The submodule is targeted via the -C flag.

#### Caller Graph (what the function calls):

```
make -C <module> graph-caller FUNC=<name> DEPTH=<number>
```
#### Callee Graph (what calls the function):

```
make -C <module> graph-callee FUNC=<name> DEPTH=<number>
```