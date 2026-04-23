# Выполненине тестового задания.

Для проверки исключил correct_public.pem и wrong_public.pem из .gitignore.

## Сборка и запуск

### Windows
```conan install . --output-folder=build --build=missing
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
.\Release\c3d_auth.exe ..\correct_public.pem
ctest -C Release --output-on-failure
```

### Linux
```conan install . --output-folder=build --build=missing
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
./c3d_auth ../correct_public.pem
ctest --output-on-failure
```


# Результаты


<img width="1907" height="722" alt="image" src="https://github.com/user-attachments/assets/b911ef30-e586-4ec5-8cf4-f01732836527" />
