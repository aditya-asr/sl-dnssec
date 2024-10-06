#! /bin/bash

### Mode
# 3 = SL-DNSSEC, 0 = QBF Sequential, 1 = QBF Parallel-2RTT, 2 = QBF Parallel-1RTT
export MODE=3

### EDNS0 buffer
# "stock" = Standard DNS with TCP fallback
export UDPSIZE="1232"

### Zone Signing Algorithm
# "FALCON512", "FALCON1024", "DILITHIUM2", "DILITHIUM5", "SPHINCS+-SHA256-128S", "RSASHA256", "ECDSA256"
export ALG="FALCON512"

export BUILDDIR="$(pwd)/build"
export WORKINGDIR="$(pwd)"

cd $WORKINGDIR
if [[ $UDPSIZE == "stock" ]]; then
  python3 build_docker_compose.py --bypass --maxudp 1232 --alg $ALG <<<"Y"
else
  python3 build_docker_compose.py --maxudp $UDPSIZE --alg $ALG --mode $MODE <<<"Y"
fi

cd $BUILDDIR
docker compose down
docker compose build
cd $WORKINGDIR
./run_exps.bash 0 10 # 10 queries