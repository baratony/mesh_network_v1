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
set(sdkVersion 2.2.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.2.0-a4)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico CACHE STRING "Board type")

# Pull in Raspberry Pi Pico SDK (must be before project)
include(pico_sdk_import.cmake)

project(Cryptographic_Functions C CXX ASM)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

# Add executable. Default name is the project name, version 0.1

add_executable(Cryptographic_Functions Cryptographic_Functions.c
    chacha20_drng.h
    chacha20_drng.c
    mini-gmp.c
    mini-gmp.h )

pico_set_program_name(Cryptographic_Functions "Cryptographic_Functions")
pico_set_program_version(Cryptographic_Functions "0.1")

# Modify the below lines to enable/disable output over UART/USB
pico_enable_stdio_usb(Cryptographic_Functions 1)
pico_enable_stdio_uart(Cryptographic_Functions 0)

# Over clock the flash to allow for higher clock speeds
pico_define_boot_stage2(slower_boot2 ${PICO_DEFAULT_BOOT_STAGE2_FILE})
target_compile_definitions(slower_boot2 PRIVATE PICO_FLASH_SPI_CLKDIV=4)

pico_set_boot_stage2(Cryptographic_Functions slower_boot2)

# Add the standard library to the build
target_link_libraries(Cryptographic_Functions
        pico_stdlib
        hardware_regs
        pico_mbedtls
    )

# Add the standard include files to the build
target_include_directories(Cryptographic_Functions PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
)

pico_add_extra_outputs(Cryptographic_Functions)

