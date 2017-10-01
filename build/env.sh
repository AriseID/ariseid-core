#!/bin/sh

set -e

if [ ! -f "build/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/_workspace"
root="$PWD"
aiddir="$workspace/src/github.com/ariseid"
if [ ! -L "$aiddir/ariseid-core" ]; then
    mkdir -p "$aiddir"
    cd "$aiddir"
    ln -s ../../../../../.ariseid-core
    cd "$root"
fi

# Set up the environment to use the workspace.
GOPATH="$workspace"
export GOPATH

# Run the command inside the workspace.
cd "$aiddir/ariseid-core"
PWD="$aiddir/ariseid-core"

# Launch the arguments with the configured environment.
exec "$@"
