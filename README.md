# MAMBO Lift

AArch64 binary lifter that consumes execution traces produces by [MAMBO Trace](https://github.com/IgWod/mambo-trace).

# Set up

MAMBO Lift requires some standard Linux packages:

```
sudo apt install cmake pkg-config python3-dev libcapstone-dev
```

Additionally a custom version of [the UNICORN project](https://www.unicorn-engine.org) is needed. It can be found [here](https://github.com/IgWod/unicorn). It can be cloned and build with following commands:

```
git clone https://github.com/IgWod/unicorn
cd unicorn; mkdir build; cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j
```

Finally, some variables need to be exported. The variables need to be set every time the lifter is used.

```
export UNICORN_ROOT=<path-to-unicorn-directory>
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$UNICORN_ROOT/build
export LIFT_ROOT=<path-to-lifter-directory>
export PYTHONPATH=$PYTHONPATH:$LIFT_ROOT/python/pyelftools/
```

Finally the lifter can be cloned and built:

```
git clone --recurse-submodule https://github.com/IgWod/mambo-lift
cd mambo-lift
make
```

## Lifting binaries

To lift the binary the binary itself and the collected traces need to be in the same directory. Then the lifting can be done by running:

```
$LIFT_ROOT/lifter <binary>
```

The generated code needs to be then post-processed:

```
$LIFT_ROOT/bash/generate-source.sh <binary>
```

And then compiled:

```
$LIFT_ROOT/bash/patch-and-compile.sh <binary>
```

## Status

This repository is a port of the original non-public code and as such is more stable but may lack some features. Most notably multi-threading support has not been tested yet.
