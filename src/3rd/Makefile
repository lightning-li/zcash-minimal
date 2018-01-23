
SNARK = snark/libsnark.a
SNARK_PATH = snark

$(SNARK):
		@echo "**************building snark now****************" && cd $(SNARK_PATH) && pwd && $(MAKE) lib STATIC=1 CURVE=ALT_BN128 NO_PROCPS=1 NO_GTEST=1 NO_SUPERCOP=1 OPTFLAGS="-O2 -march=x86-64" && $(MAKE) install PREFIX=.

