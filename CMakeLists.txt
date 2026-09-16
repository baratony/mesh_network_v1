# Generated Cmake Pico project file

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Initialise pico_sdk from installed location
# (note this can come from environment, CMake cache etc)

# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.3.0)
set(toolchainVersion 15_2_Rel1)
set(picotoolVersion 2.3.0)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico CACHE STRING "Board type")

# Pull in Raspberry Pi Pico SDK (must be before project)
include(pico_sdk_import.cmake)

project(mesh_network_v1 C CXX ASM)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

add_library(ethernet_setup STATIC
    Ethernet_FTP/ethernet_setup.c
    Ethernet_FTP/w5500.c
    Ethernet_FTP/wizchip_conf.c
    Ethernet_FTP/socket.c
)

target_include_directories(ethernet_setup PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/Ethernet_FTP
)

target_link_libraries(ethernet_setup
    PUBLIC
    pico_stdlib
    hardware_spi
    hardware_gpio
)

# Add executable. Default name is the project name, version 0.1

add_executable(mesh_network_v1
    mesh_network_v1.c
    Radio/ebyte_e32.c
    Radio/radio_packet_protocol.c
    Ethernet_FTP/ftp_client.c
)

pico_set_program_name(mesh_network_v1 "mesh_network_v1")
pico_set_program_version(mesh_network_v1 "0.1")

# Modify the below lines to enable/disable output over UART/USB
pico_enable_stdio_uart(mesh_network_v1 0)
pico_enable_stdio_usb(mesh_network_v1 1)

# Add the standard library to the build
target_link_libraries(mesh_network_v1
        pico_stdlib)

target_link_libraries(mesh_network_v1
    ethernet_setup
    hardware_gpio
    hardware_rtc
    hardware_uart
    pico_rand)

# Add the standard include files to the build
target_include_directories(mesh_network_v1 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
)

pico_add_extra_outputs(mesh_network_v1)

