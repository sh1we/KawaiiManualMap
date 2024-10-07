#include <Windows.h>
#include <iostream>
#include <fstream> //  Вот и он!  (☆ω☆)
#include <vector>
#include <TlHelp32.h>
#include <string>
#include <winternl.h>
#include <Psapi.h>

//  Кавайная структура для Manual Mapping  💖
struct KawaiiMappedModule {
	HMODULE hModule;
	DWORD64 baseAddress;
	DWORD sizeOfImage;
};

DWORD GetProcessIdByName(const std::wstring& processName) {
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (snapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Ошибка создания снапшота процессов!  (T_T)" << std::endl;
		return 0;
	}


	if (!Process32FirstW(snapshot, &entry)) {
		CloseHandle(snapshot);
		std::cerr << "Ошибка получения первого процесса!  (╥﹏╥)" << std::endl;
		return 0;
	}

	do {
		if (processName == entry.szExeFile) {
			CloseHandle(snapshot);
			return entry.th32ProcessID;
		}
	} while (Process32NextW(snapshot, &entry));

	CloseHandle(snapshot);

	//  Если процесс не найден
	return 0;
}

// Перегрузка для использования со std::string
DWORD GetProcessIdByName(const std::string& processName)
{
	std::wstring widestr = std::wstring(processName.begin(), processName.end());
	return GetProcessIdByName(widestr);
}

template <typename T>
T ReadMemory(HANDLE hProcess, DWORD64 address)
{
	T buffer;
	SIZE_T bytesRead;
	ReadProcessMemory(hProcess, (LPCVOID)address, &buffer, sizeof(buffer), &bytesRead);
	return buffer;
}

template <typename T>
bool WriteMemory(HANDLE hProcess, DWORD64 address, T value)
{
	SIZE_T bytesWritten;
	return WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(value), &bytesWritten);
}


DWORD64 GetModuleBase(HANDLE hProcess, const wchar_t* moduleName)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_64BIT | LIST_MODULES_ALL))
	{
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{

			wchar_t szModName[MAX_PATH];

			// Получаем полный пуль к модулю.

			if (GetModuleFileNameExW(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(wchar_t)))
			{
				std::wstring wstrModuleName = moduleName;
				if (std::wstring(szModName).find(wstrModuleName) != std::string::npos)
				{
					return (DWORD64)hMods[i];
				}

			}
		}
	}
	return 0;
}


//  Функция для Manual Mapping (немного сложно, но очень круто!)  😎
KawaiiMappedModule KawaiiManualMap(const char* dllPath, HANDLE hProcess) {
	// 1. Читаем файл DLL в память
	std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);
	std::vector<BYTE> buffer(size);
	if (!file.read((char*)buffer.data(), size)) {
		std::cerr << "Ошибка чтения DLL! (T_T)" << std::endl;
		return { nullptr, 0, 0 };
	}


	// 2. Парсим PE заголовки
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer.data();
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)buffer.data() + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);


	// 3. Выделяем память в целевом процессе
	DWORD64 baseAddress = (DWORD64)VirtualAllocEx(hProcess, nullptr, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!baseAddress) {
		std::cerr << "Ошибка выделения памяти! (╥﹏╥)" << std::endl;
		return { nullptr, 0, 0 };
	}

	// 4. Копируем заголовки
	if (!WriteProcessMemory(hProcess, (LPVOID)baseAddress, buffer.data(), ntHeaders->OptionalHeader.SizeOfHeaders, nullptr)) {
		std::cerr << "Ошибка копирования заголовков! (ಥ_ಥ)" << std::endl;
		VirtualFreeEx(hProcess, (LPVOID)baseAddress, 0, MEM_RELEASE);
		return { nullptr, 0, 0 };
	}

	// 5. Копируем секции
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		if (!WriteProcessMemory(hProcess, (LPVOID)(baseAddress + sectionHeader[i].VirtualAddress), buffer.data() + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData, nullptr)) {
			std::cerr << "Ошибка копирования секции! (o_o)" << std::endl;
			VirtualFreeEx(hProcess, (LPVOID)baseAddress, 0, MEM_RELEASE);
			return { nullptr, 0, 0 };
		}
	}

	// 6. Фиксация импорта (это  очень важно!  (☆ω☆))
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (importDescriptor->Name) {
		char* dllName = (char*)(baseAddress + importDescriptor->Name);
		HMODULE hDll = LoadLibraryA(dllName);

		if (!hDll) {
			std::cerr << "Не удалось загрузить DLL " << dllName << "! (T_T)" << std::endl;
			VirtualFreeEx(hProcess, (LPVOID)baseAddress, 0, MEM_RELEASE);
			return { nullptr, 0, 0 };
		}

		PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor->FirstThunk);

		while (thunkData->u1.AddressOfData) {
			if (IMAGE_SNAP_BY_ORDINAL(thunkData->u1.Ordinal)) {
				iat->u1.Function = (DWORD64)GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(thunkData->u1.Ordinal));
			}
			else {
				PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(baseAddress + thunkData->u1.AddressOfData);
				iat->u1.Function = (DWORD64)GetProcAddress(hDll, importByName->Name);
			}

			if (!iat->u1.Function) {
				std::cerr << "Не удалось получить адрес функции! (╥﹏╥)" << std::endl;
				VirtualFreeEx(hProcess, (LPVOID)baseAddress, 0, MEM_RELEASE);
				return { nullptr, 0, 0 };
			}

			thunkData++;
			iat++;
		}

		importDescriptor++;
	}


	// 7. Фиксация релокаций (тоже  очень важно!  (>.<))

	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(baseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	while (relocation->VirtualAddress) {
		DWORD delta = (DWORD)(baseAddress - ntHeaders->OptionalHeader.ImageBase);
		DWORD size = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD relocationData = (PWORD)(relocation + 1);


		for (DWORD i = 0; i < size; ++i) {
			DWORD type = (relocationData[i] >> 12);
			DWORD offset = (relocationData[i] & 0xFFF);


			if (type == IMAGE_REL_BASED_HIGHLOW) {
				DWORD_PTR* address = (DWORD_PTR*)(baseAddress + relocation->VirtualAddress + offset);
				*address += delta;
			}
			// ... (Другие типы релокаций) ... 

		}


		relocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocation + relocation->SizeOfBlock);
	}


	// 6. Запускаем DLL в целевом процессе
	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)(baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint), nullptr, 0, nullptr);
	if (!hThread) {
		std::cerr << "Ошибка создания потока! (╯︵╰,)" << std::endl;
		VirtualFreeEx(hProcess, (LPVOID)baseAddress, 0, MEM_RELEASE);
		return { nullptr, 0, 0 };
	}

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	KawaiiMappedModule module = { (HMODULE)baseAddress, baseAddress, ntHeaders->OptionalHeader.SizeOfImage };
	return module;

}
//  Функция для сокрытия модуля (хитро!  (¬‿¬))
void KawaiiHideModule(KawaiiMappedModule module, HANDLE hProcess) {
	//  Получаем адрес InLoadOrderModuleList в PEB
	DWORD64 pebAddress;
	if (!ReadProcessMemory(hProcess, (LPCVOID)(__readgsqword(0x60) + 0x18), &pebAddress, sizeof(pebAddress), nullptr)) {
		// Обработка ошибки
		return;
	}

	DWORD64 ldrAddress;
	if (!ReadProcessMemory(hProcess, (LPCVOID)(pebAddress + 0x18), &ldrAddress, sizeof(ldrAddress), nullptr)) {
		// Обработка ошибки
		return;
	}

	DWORD64 inLoadOrderModuleListHead;
	if (!ReadProcessMemory(hProcess, (LPCVOID)(ldrAddress + 0x20), &inLoadOrderModuleListHead, sizeof(inLoadOrderModuleListHead), nullptr)) {
		// Обработка ошибки
		return;
	}

	// Идем по списку модулей
	DWORD64 currentModule = inLoadOrderModuleListHead;
	DWORD64 previousModule = 0;

	while (currentModule)
	{
		LDR_DATA_TABLE_ENTRY entry;

		if (!ReadProcessMemory(hProcess, (LPCVOID)currentModule, &entry, sizeof(entry), nullptr)) {
			// Обработка ошибки
			break;
		}



		if (entry.DllBase == module.baseAddress) {
			//  Нашли наш модуль!  (⌒∇⌒)  Теперь нужно его удалить!

			DWORD64 flink = currentModule + 0x18;
			DWORD64 blink = currentModule + 0x20;
			DWORD64 flinkValue;
			DWORD64 blinkValue;

			//  Читаем значения flink и blink
			ReadProcessMemory(hProcess, (LPCVOID)flink, &flinkValue, sizeof(flinkValue), nullptr);
			ReadProcessMemory(hProcess, (LPCVOID)blink, &blinkValue, sizeof(blinkValue), nullptr);


			// Переписываем flink предыдущего модуля на flink текущего
			if (!WriteProcessMemory(hProcess, (LPVOID)(previousModule + 0x18), &flinkValue, sizeof(flinkValue), nullptr)) {
				// Обработка ошибки
				break;

			}


			// Переписываем blink следующего модуля на blink текущего
			if (!WriteProcessMemory(hProcess, (LPVOID)(flinkValue + 0x20), &blinkValue, sizeof(blinkValue), nullptr)) {
				// Обработка ошибки
				break;
			}



			break;
		}

		previousModule = currentModule;
		currentModule = entry.InLoadOrderLinks.Flink;


	}
}


//  Функция для перехвата функции (с использованием хуков)  😈
void* KawaiiHookFunction(DWORD64 targetAddress, void* hookedFunction, HANDLE hProcess) {
	//  Размер  jmp-инструкции (5 байт)
	constexpr size_t jmpInstructionSize = 5;


	//  Выделяем память для  кавайного  трамплина в целевом процессе
	void* trampoline = VirtualAllocEx(hProcess, nullptr, jmpInstructionSize + sizeof(targetAddress), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!trampoline) {
		std::cerr << "Ошибка выделения памяти для трамплина! (T_T)" << std::endl;
		return nullptr;
	}


	//  Сохраняем оригинальные байты
	BYTE originalBytes[jmpInstructionSize];
	ReadProcessMemory(hProcess, (LPCVOID)targetAddress, originalBytes, jmpInstructionSize, nullptr);



	//  Формируем  jmp-инструкцию  к нашей функции
	BYTE jmpInstruction[jmpInstructionSize] = { 0xE9 };  //  Opcode для jmp near
	DWORD relativeAddress = (DWORD)((DWORD_PTR)hookedFunction - (DWORD_PTR)targetAddress - jmpInstructionSize);
	memcpy(jmpInstruction + 1, &relativeAddress, sizeof(relativeAddress));



	//  Записываем  jmp-инструкцию в целевую функцию
	WriteProcessMemory(hProcess, (LPVOID)targetAddress, jmpInstruction, jmpInstructionSize, nullptr);



	// Копируем оригинальные байты в трамплин + добавляем jmp на продолжение оригинальной функции.

	WriteProcessMemory(hProcess, trampoline, originalBytes, jmpInstructionSize, nullptr);


	BYTE jmpBackInstruction[jmpInstructionSize] = { 0xE9 };
	DWORD relativeAddressBack = (DWORD)((DWORD_PTR)targetAddress + jmpInstructionSize - (DWORD_PTR)trampoline - jmpInstructionSize);

	memcpy(jmpBackInstruction + 1, &relativeAddressBack, sizeof(DWORD));

	WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)trampoline + jmpInstructionSize), jmpBackInstruction, jmpInstructionSize, nullptr);


	//  Возвращаем адрес  кавайного  трамплина
	return trampoline;
}


//  Главная функция (самое интересное!)  (☆ω☆)
int main() {
	//  Получаем ID процесса игры (например, CS:GO)
	DWORD processId = GetProcessIdByName("csgo.exe");

	if (!processId) {
		std::cerr << "Игра не найдена!  (T_T)" << std::endl;
		return 1;
	}

	//  Открываем процесс с нужными правами
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	if (!hProcess) {
		std::cerr << "Не удалось открыть процесс!  (╥﹏╥)" << std::endl;
		return 1;
	}

	//  Путь к нашей кавайной DLL  💖
	const char* dllPath = "kawaii_cheat.dll";

	//  Инжектим DLL с помощью Manual Mapping
	KawaiiMappedModule mappedModule = KawaiiManualMap(dllPath, hProcess);

	if (!mappedModule.hModule) {
		std::cerr << "Не удалось инжектировать DLL!  (ಥ_ಥ)" << std::endl;
		CloseHandle(hProcess);
		return 1;
	}

	//  Прячем модуль от VAC  (хи-хи!)  (⁄⁄>⁄ ▽ ⁄<⁄⁄)
	KawaiiHideModule(mappedModule, hProcess);

	//  Адрес целевой функции (нужно найти в дизассемблере)
	DWORD64 targetAddress = 0x1234567890ABCDEF; //  Пример адреса

	//  Перехватываем функцию
	KawaiiHookFunction(targetAddress, HookedFunction, hProcess);

	std::cout << "Инжектор успешно запущен!  (⌒∇⌒)" << std::endl;

	//  Бесконечный цикл (можно добавить обработку нажатий клавиш)
	while (true) {
		Sleep(1000);
	}


	//  Закрываем хэндл процесса (хотя это уже не важно, хи-хи!)  😜
	CloseHandle(hProcess);

	return 0;
}


// Заглушка для функции HookedFunction. Ее код должен быть в инжектируемой DLL
int __cdecl HookedFunction(int a, int b)
{
	return 0;
}