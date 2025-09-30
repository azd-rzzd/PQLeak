# Hey Emacs, this is a -*- makefile -*-
#----------------------------------------------------------------------------
#
# Makefile for ChipWhisperer SimpleSerial-AES Program
#
#----------------------------------------------------------------------------
# On command line:
#
# make all = Make software.
#
# make clean = Clean out built project files.
#
# make coff = Convert ELF to AVR COFF.
#
# make extcoff = Convert ELF to AVR Extended COFF.
#
# make program = Download the hex file to the device, using avrdude.
#                Please customize the avrdude settings below first!
#
# make debug = Start either simulavr or avarice as specified for debugging,
#              with avr-gdb or avr-insight as the front end for debugging.
#
# make filename.s = Just compile filename.c into the assembler code only.
#
# make filename.i = Create a preprocessed source file for use in submitting
#                   bug reports to the GCC project.
#
# To rebuild project do "make clean" then "make all".
#----------------------------------------------------------------------------

# Target file name (without extension).
# This is the base name of the compiled .hex file.
#TARGET = simpleserial-kyber
#CRYPTO_OPTIONS = kyber768
# List C source files here.
# Header files (.h) are automatically pulled in.
#SRC += ${TARGET}.c
#SRC+=$(wildcard $(CRYPTO_PATH)/crypto_kem/kyber768/m4fspeed/*.c)
#SRC+=$(wildcard $(CRYPTO_PATH)/common/*.c)
#SRC+=$(wildcard $(CRYPTO_PATH)/common/mps2/*.c)

#ASRC+=$(wildcard $(CRYPTO_PATH)/crypto_kem/kyber768/m4/*.S)
#ASRC+=$(wildcard $(CRYPTO_PATH)/common/*.S)
#ASRC+=$(wildcard $(CRYPTO_PATH)/common/mps2/*.S)

#EXTRAINCDIRS += $(CRYPTO_PATH)/crypto_kem/kyber768/m4fspeed/
#EXTRAINCDIRS += $(CRYPTO_PATH)/common/
#EXTRAINCDIRS += $(CRYPTO_PATH)/common/mps2/
#EXTRAINCDIRS += $(CRYPTO_PATH)/libopencm3/include
#EXTRAINCDIRS += $(CRYPTO_PATH)/libopencm3/lib



# Target file name (without extension).
# This is the base name of the compiled .hex file.
TARGET = simpleserial-kyber
CRYPTO_TARGET = NONE
PLATFORM=CW308_STM32F4
# List C source files here.
# Header files (.h) are automatically pulled in. SRC is a flag
# # Source adds .c source files for build 
# SRC += ${TARGET}.c
# SRC+=$(wildcard $(CRYPTO_PATH)/crypto_kem/kyber768/m4fspeed/*.c)
# SRC+=$(wildcard $(CRYPTO_PATH)/common/*.c)
# #SRC+=$(wildcard $(CRYPTO_PATH)/mupq/common/*.c)

# # Source adds .S source files for build 
# ASRC+=$(wildcard $(CRYPTO_PATH)/crypto_kem/kyber768/m4fspeed/*.S)
# ASRC+=$(wildcard $(CRYPTO_PATH)/common/*.S)

# # all the folders that contains imporant .h files
# EXTRAINCDIRS += $(CRYPTO_PATH)/crypto_kem/kyber768/m4fspeed/
# EXTRAINCDIRS += $(CRYPTO_PATH)/common/
# EXTRAINCDIRS += $(CRYPTO_PATH)/libopencm3/include/
# #EXTRAINCDIRS += $(CRYPTO_PATH)/mupq/common/


# Source adds .c source files for build 
SRC += ${TARGET}.c
SRC+=$(wildcard pqm4/crypto_kem/ml-kem-768/m4fspeed/*.c)
SRC+=$(wildcard pqm4/common/*.c)
SRC+= pqm4/libopencm3/lib/stm32/common/rng_common_v1.c
# SRC+=$(wildcard pqm4/mupq/common/*.c)
# SRC+=$(wildcard pqm4/crypto_kem/kyber768/m4fspeed/*.i)
# SRC+=common/aes.c common/randombytes.c
SRC+=pqm4/mupq/common/fips202.c


# Source adds .S source files for build 
ASRC+=$(wildcard pqm4/crypto_kem/ml-kem-768/m4fspeed/*.S)
ASRC+=$(wildcard pqm4/common/*.S)
ASRC+=$(wildcard pqm4/libopencm3/include/libopencm3/stm32/common/*.S)
# ASRC+=$(wildcard pqm4/mupq/common/*.S)
# ASRC+=pqm4/crypto_kem/kyber768/m4fspeed/matacc.i

# all the folders that contains imporant .h files
EXTRAINCDIRS += pqm4/crypto_kem/ml-kem-768/m4fspeed/
#EXTRAINCDIRS += pqm4/common/
EXTRAINCDIRS += pqm4/mupq/common
EXTRAINCDIRS += pqm4/libopencm3/include/
EXTRAINCDIRS += pqm4/libopencm3/lib/


# -----------------------------------------------------------------------------
EXTRA_OPTS = NO_EXTRA_OPTS
CFLAGS += -D$(EXTRA_OPTS) -DSTM32F4 -mfloat-abi=hard -mfpu=fpv4-sp-d16
FPUUSE = 0

${info Building for platform ${PLATFORM} with CRYPTO_TARGET=$(CRYPTO_TARGET)}

#Add simpleserial project to build
include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.

include $(FIRMWAREPATH)/Makefile.inc

