savedcmd_arch/arm64/boot/dts/allwinner/overlay/sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo := gcc -E -Wp,-MMD,arch/arm64/boot/dts/allwinner/overlay/.sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo.d.pre.tmp -nostdinc -I./scripts/dtc/include-prefixes -undef -D__DTS__ -x assembler-with-cpp -o arch/arm64/boot/dts/allwinner/overlay/.sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo.dts.tmp arch/arm64/boot/dts/allwinner/overlay/sun50i-h5-cpu-clock-1.0GHz-1.1v.dtso ; ./scripts/dtc/dtc -o arch/arm64/boot/dts/allwinner/overlay/sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo -b 0 -iarch/arm64/boot/dts/allwinner/overlay/ -i./scripts/dtc/include-prefixes -Wno-interrupt_provider -Wno-unique_unit_address -Wno-unit_address_vs_reg -Wno-avoid_unnecessary_addr_size -Wno-alias_paths -Wno-graph_child_address -Wno-simple_bus_reg  -@  -d arch/arm64/boot/dts/allwinner/overlay/.sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo.d.dtc.tmp arch/arm64/boot/dts/allwinner/overlay/.sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo.dts.tmp ; cat arch/arm64/boot/dts/allwinner/overlay/.sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo.d.pre.tmp arch/arm64/boot/dts/allwinner/overlay/.sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo.d.dtc.tmp > arch/arm64/boot/dts/allwinner/overlay/.sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo.d

source_arch/arm64/boot/dts/allwinner/overlay/sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo := arch/arm64/boot/dts/allwinner/overlay/sun50i-h5-cpu-clock-1.0GHz-1.1v.dtso

deps_arch/arm64/boot/dts/allwinner/overlay/sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo := \

arch/arm64/boot/dts/allwinner/overlay/sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo: $(deps_arch/arm64/boot/dts/allwinner/overlay/sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo)

$(deps_arch/arm64/boot/dts/allwinner/overlay/sun50i-h5-cpu-clock-1.0GHz-1.1v.dtbo):
