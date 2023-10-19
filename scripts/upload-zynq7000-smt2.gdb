#openocd gdb server with onboard zynq7000 Zedboard Digilent FTDI-based SMT2 JTAG
target extended-remote localhost:3333
set verbose on

set output-radix 16
set pagination on

#Reset USB phy
set *((u32*)0xE000A040) = 0

monitor adapter srst pulse_width 250
monitor adapter srst delay 250

monitor reset
monitor halt

load

monitor resume
detach
