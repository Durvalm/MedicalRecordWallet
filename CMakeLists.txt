cmake_minimum_required(VERSION 3.16)
project(MedicalRecordWalletApp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)

# Enable Qt's MOC (Meta-Object Compiler)
set(CMAKE_AUTOMOC ON)

# Add executable
add_executable(MedicalRecordWalletApp 
	src/main.cpp
	src/LoginDialog.cpp
	src/LoginDialog.h


)

#Making sure headers in src/ are visible
target_include_directories(MedicalRecordWalletApp PRIVATE src)

# Link Qt libraries
target_link_libraries(MedicalRecordWalletApp Qt6::Core Qt6::Widgets)