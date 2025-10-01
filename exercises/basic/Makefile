# SPDX-License-Identifier: Apache-2.0
# BMV2_SWITCH_EXE = simple_switch_grpc
# TOPO = triangle-topo/topology.json

# include ../../utils/Makefile

# SPDX-License-Identifier: Apache-2.0
BMV2_SWITCH_EXE = simple_switch_grpc
TOPO ?= hw3-1,3-2/2h4w.json

include ../../utils/Makefile

.PHONY: 1-2 1-3 2-1 2-2 3-1 3-2
1-2:
	make clean
	make run TOPO=hw1-2/2h4w.json

1-3:
	make clean
	make run TOPO=hw1-3/2h4w.json

2-1:
	make clean
	make run TOPO=hw2-1/2h4w.json

2-2:
	make clean
	make run TOPO=hw2-2/2h4w.json

3-1:
	make clean
	make run TOPO=hw3-1,3-2/2h4w.json

3-2:
	make clean
	make run TOPO=hw3-1,3-2/2h4w.json