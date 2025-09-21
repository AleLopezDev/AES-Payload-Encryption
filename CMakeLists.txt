cmake_minimum_required(VERSION 3.16)
project(EncriptarAES C)

set(CMAKE_C_STANDARD 11)

add_executable(EncriptarAES
        main.c
        crypto/aes.c
)

# Para que encuentre crypto/aes.h
target_include_directories(EncriptarAES PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/crypto)

# Activar modo CBC de TinyAES
target_compile_definitions(EncriptarAES PRIVATE AES128=1 CBC=1)

# BCrypt para generar IV aleatorio en Windows
target_link_libraries(EncriptarAES PRIVATE bcrypt)

# (Opcional) definir versión mínima de Windows por MinGW
target_compile_definitions(EncriptarAES PRIVATE _WIN32_WINNT=0x0601)
