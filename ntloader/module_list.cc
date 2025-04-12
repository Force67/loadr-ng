// Copyright (c) [Your Name or Organization]. All rights reserved.
// Licensed under [Your License, if applicable].

#ifndef MODULE_LIST_H_
#define MODULE_LIST_H_

#include <sstream>
#include <string>
#include <vector>

#include "loader.h"
#include "module_list.h"

extern "C" {
// Windows API and internal structure declarations.
HMODULE LdrGetDllHandle(PWSTR dll_path, PULONG dll_characteristics,
                        PUNICODE_STRING dll_name, PVOID* dll_handle);

NTSTATUS RtlHashUnicodeString(PUNICODE_STRING string, BOOLEAN case_insensitive,
                              ULONG hash_algorithm, PULONG hash_value);

#if 1
typedef struct _RTL_BALANCED_NODE {
  union {
    struct _RTL_BALANCED_NODE* children[2];
    struct {
      struct _RTL_BALANCED_NODE* left;
      struct _RTL_BALANCED_NODE* right;
    };
  };
  union {
    UCHAR red : 1;
    UCHAR balance : 2;
    ULONG_PTR parent_value;
  };
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE {
  PRTL_BALANCED_NODE root;
  PRTL_BALANCED_NODE min;
} RTL_RB_TREE, *PRTL_RB_TREE;

VOID RtlRbInsertNodeEx(PRTL_RB_TREE tree, PRTL_BALANCED_NODE parent,
                       BOOLEAN right, PRTL_BALANCED_NODE node);
#endif

#define LDRP_IMAGE_DLL 0x00000004
#define LDRP_ENTRY_INSERTED 0x00008000
#define LDRP_ENTRY_PROCESSED 0x00004000
#define LDRP_PROCESS_ATTACH_CALLED 0x00080000

#define LDR_HASH_TABLE_ENTRIES 32

#define RtlInitializeListEntry(entry) \
  ((entry)->Blink = (entry)->Flink = (entry))

typedef enum _LDR_DLL_LOAD_REASON {
  LoadReasonStaticDependency,
  LoadReasonStaticForwarderDependency,
  LoadReasonDynamicForwarderDependency,
  LoadReasonDelayloadDependency,
  LoadReasonDynamicLoad,
  LoadReasonAsImageLoad,
  LoadReasonAsDataLoad,
  LoadReasonEnclavePrimary,  // REDSTONE3
  LoadReasonEnclaveDependency,
  LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON,
    *PLDR_DLL_LOAD_REASON;

typedef enum _LDR_DDAG_STATE {
  LdrModulesMerged = -5,
  LdrModulesInitError = -4,
  LdrModulesSnapError = -3,
  LdrModulesUnloaded = -2,
  LdrModulesUnloading = -1,
  LdrModulesPlaceHolder = 0,
  LdrModulesMapping = 1,
  LdrModulesMapped = 2,
  LdrModulesWaitingForDependencies = 3,
  LdrModulesSnapping = 4,
  LdrModulesSnapped = 5,
  LdrModulesCondensed = 6,
  LdrModulesReadyToInit = 7,
  LdrModulesInitializing = 8,
  LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDR_SERVICE_TAG_RECORD {
  struct _LDR_SERVICE_TAG_RECORD* next;
  ULONG service_tag;
} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST {
  PSINGLE_LIST_ENTRY tail;
} LDRP_CSLIST, *PLDRP_CSLIST;

typedef struct _LDR_DDAG_NODE {
  LIST_ENTRY modules;
  PLDR_SERVICE_TAG_RECORD service_tag_list;
  ULONG load_count;
  ULONG load_while_unloading_count;
  ULONG lowest_link;
  union {
    LDRP_CSLIST dependencies;
    SINGLE_LIST_ENTRY removal_link;
  };
  LDRP_CSLIST incoming_dependencies;
  LDR_DDAG_STATE state;
  SINGLE_LIST_ENTRY condense_link;
  ULONG preorder_number;
} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

struct InternalLdrDataTableEntry {
  LIST_ENTRY in_load_order_links;
  LIST_ENTRY in_memory_order_links;
  union {
    LIST_ENTRY in_initialization_order_links;
    LIST_ENTRY in_progress_links;
  };
  PVOID dll_base;
  void* entry_point;
  ULONG size_of_image;
  UNICODE_STRING full_dll_name;
  UNICODE_STRING base_dll_name;
  union {
    UCHAR flag_group[4];
    ULONG flags;
    struct {
      ULONG packaged_binary : 1;
      ULONG marked_for_removal : 1;
      ULONG image_dll : 1;
      ULONG load_notifications_sent : 1;
      ULONG telemetry_entry_processed : 1;
      ULONG process_static_import : 1;
      ULONG in_legacy_lists : 1;
      ULONG in_indexes : 1;
      ULONG shim_dll : 1;
      ULONG in_exception_table : 1;
      ULONG reserved_flags1 : 2;
      ULONG load_in_progress : 1;
      ULONG load_config_processed : 1;
      ULONG entry_processed : 1;
      ULONG protect_delay_load : 1;
      ULONG reserved_flags3 : 2;
      ULONG dont_call_for_threads : 1;
      ULONG process_attach_called : 1;
      ULONG process_attach_failed : 1;
      ULONG cor_deferred_validate : 1;
      ULONG cor_image : 1;
      ULONG dont_relocate : 1;
      ULONG cor_il_only : 1;
      ULONG chpe_image : 1;
      ULONG reserved_flags5 : 2;
      ULONG redirected : 1;
      ULONG reserved_flags6 : 2;
      ULONG compat_database_processed : 1;
    };
  };
  USHORT obsolete_load_count;
  USHORT tls_index;
  LIST_ENTRY hash_links;
  ULONG time_date_stamp;
  struct _ACTIVATION_CONTEXT* entry_point_activation_context;
  PVOID lock;  // RtlAcquireSRWLockExclusive.
  _LDR_DDAG_NODE* ddag_node;
  LIST_ENTRY node_module_link;
  struct _LDRP_LOAD_CONTEXT* load_context;
  PVOID parent_dll_base;
  PVOID switch_back_context;
  RTL_BALANCED_NODE base_address_index_node;
  RTL_BALANCED_NODE mapping_info_index_node;
  ULONG_PTR original_base;
  LARGE_INTEGER load_time;
  ULONG base_name_hash_value;
  LDR_DLL_LOAD_REASON load_reason;
  ULONG implicit_path_options;
  ULONG reference_count;
  ULONG dependent_load_flags;
  UCHAR signing_level;  // Since REDSTONE2.
};

typedef struct _InternalPebLdrData {
  ULONG length;
  UCHAR initialized;
  PVOID ss_handle;
  LIST_ENTRY in_load_order_module_list;
  LIST_ENTRY in_memory_order_module_list;
  LIST_ENTRY in_initialization_order_module_list;
  PVOID entry_in_progress;
} InternalPebLdrData, *PInternalPebLdrData;

typedef struct _InternalPeb {
  UCHAR inherited_address_space;
  UCHAR read_image_file_exec_options;
  UCHAR being_debugged;
  UCHAR bit_field;
  ULONG image_uses_large_pages : 1;
  ULONG is_protected_process : 1;
  ULONG is_legacy_process : 1;
  ULONG is_image_dynamically_relocated : 1;
  ULONG spare_bits : 4;
  PVOID mutant;
  PVOID image_base_address;
  PInternalPebLdrData ldr;
  PRTL_USER_PROCESS_PARAMETERS process_parameters;
  PVOID sub_system_data;
  PVOID process_heap;
  PRTL_CRITICAL_SECTION fast_peb_lock;
  PVOID atl_thunk_s_list_ptr;
  PVOID IFEO_key;
  ULONG cross_process_flags;
  ULONG process_in_job : 1;
  ULONG process_initializing : 1;
  ULONG reserved_bits0 : 30;
  union {
    PVOID kernel_callback_table;
    PVOID user_shared_info_ptr;
  };
  ULONG system_reserved[1];
  ULONG spare_ulong;
} InternalPeb, *PInternalPeb;
}  // extern "C"

// Extracts the base name from a full Unicode string path.
UNICODE_STRING ExtractBaseName(UNICODE_STRING* full_name) {
  UNICODE_STRING base_name = {0};
  if (full_name->Buffer) {
    PWSTR last_backslash = wcsrchr(full_name->Buffer, L'\\');
    if (last_backslash) {
      base_name.Buffer = last_backslash + 1;
      base_name.Length =
          full_name->Length -
          (USHORT)((last_backslash + 1 - full_name->Buffer) * sizeof(WCHAR));
      base_name.MaximumLength = base_name.Length + sizeof(WCHAR);
    } else {
      base_name = *full_name;
    }
  }
  return base_name;
}

#define HASH_STRING_ALGORITHM_DEFAULT 0x00000000

// Computes a hash for a Unicode string.
ULONG32 NTAPI LdrpHashUnicodeString(PUNICODE_STRING name_string) {
  ULONG result = 0;
  if (!SUCCEEDED(RtlHashUnicodeString(
          name_string, TRUE, HASH_STRING_ALGORITHM_DEFAULT, &result))) {
    result = MINLONG;
  }
  return result;
}

// Finds the .text section of ntdll.dll.
void* FindNtdllTextSection(uint64_t* text_size) {
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  if (!ntdll) return nullptr;

  // Parse PE headers.
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)ntdll + dos->e_lfanew);
  PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

  // Find .text section.
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (memcmp(sections[i].Name, ".text", 5) == 0) {
      *text_size = sections[i].SizeOfRawData;
      return (void*)((uintptr_t)ntdll + sections[i].VirtualAddress);
    }
  }
  return nullptr;
}

// Calculates a hash value for the base name.
ULONG CalculateBaseNameHashValue(const UNICODE_STRING* base_name) {
  ULONG hash = 0;
  for (USHORT i = 0; i < base_name->Length / sizeof(WCHAR); ++i) {
    hash ^= (hash << 7) ^ base_name->Buffer[i];
  }
  return hash;
}

// Finds an LDR data table entry by base name.
InternalLdrDataTableEntry* FindLdrTableEntry(PCWSTR base_name) {
  PInternalPeb peb;
  InternalLdrDataTableEntry* cur_entry;
  PLIST_ENTRY list_head, list_entry;

  peb = (PInternalPeb)__readgsqword(0x60);
  if (peb == NULL) {
    return NULL;
  }

  list_head = &peb->ldr->in_load_order_module_list;
  list_entry = list_head->Flink;

  do {
    cur_entry = CONTAINING_RECORD(list_entry, InternalLdrDataTableEntry,
                                  in_load_order_links);
    list_entry = list_entry->Flink;

    auto wide_string_length = [](PCWSTR str) { return wcslen(str); };
    auto len = wide_string_length(base_name) * sizeof(WCHAR);
    BOOL base_name_match =
        ::RtlCompareMemory(base_name, cur_entry->base_dll_name.Buffer,
                         wide_string_length(base_name) * sizeof(WCHAR)) == len;

    if (base_name_match == TRUE) {
      return cur_entry;
    }
  } while (list_entry != list_head);

  return NULL;
}

// Finds the hash table for LDR entries.
PLIST_ENTRY FindHashTable() {
  PLIST_ENTRY list = NULL;
  PLIST_ENTRY head = NULL;
  PLIST_ENTRY entry = NULL;
  InternalLdrDataTableEntry* current_entry = NULL;

  PInternalPeb peb = (PInternalPeb)__readgsqword(0x60);
  if (!peb || !peb->ldr) {
    return NULL;
  }

  head = &peb->ldr->in_initialization_order_module_list;
  entry = head->Flink;

  do {
    current_entry = CONTAINING_RECORD(entry, InternalLdrDataTableEntry,
                                      in_initialization_order_links);
    entry = entry->Flink;

    if (current_entry->hash_links.Flink == &current_entry->hash_links) {
      continue;
    }

    list = current_entry->hash_links.Flink;

    if (list->Flink == &current_entry->hash_links) {
      ULONG raw_hash = LdrpHashUnicodeString(&current_entry->base_dll_name);
      ULONG hash = raw_hash & (LDR_HASH_TABLE_ENTRIES - 1);

      list = (PLIST_ENTRY)((SIZE_T)current_entry->hash_links.Flink -
                           hash * sizeof(LIST_ENTRY));
      break;
    }

    list = NULL;
  } while (head != entry);

  if (!list) {
    OutputDebugStringW(L"Failed to locate LdrpHashTable\n");
  }
  return list;
}

// Inserts an entry into a list tail.
NTSTATUS InsertTailList(PLIST_ENTRY list_head, PLIST_ENTRY entry) {
  if (list_head == NULL || entry == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  __try {
    PLIST_ENTRY blink = list_head->Blink;
    entry->Flink = list_head;
    entry->Blink = blink;
    blink->Flink = entry;
    list_head->Blink = entry;
    return 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return STATUS_ACCESS_VIOLATION;
  }
}

#define RVA(type, base_addr, rva) (type)((ULONG_PTR)base_addr + rva)

// Finds the module base address index.
PRTL_RB_TREE FindModuleBaseAddressIndex() {
  SIZE_T end = NULL;
  PRTL_BALANCED_NODE node = NULL;
  PRTL_RB_TREE mod_base_addr_index = NULL;

  InternalLdrDataTableEntry* ldr_entry = FindLdrTableEntry(L"ntdll.dll");
  node = &ldr_entry->base_address_index_node;

  do {
    node = (PRTL_BALANCED_NODE)(node->parent_value & (~7));
  } while (node->parent_value & (~7));

  if (!node->red) {
    DWORD len = NULL;
    SIZE_T begin = NULL;
    PIMAGE_NT_HEADERS nt_headers =
        RVA(PIMAGE_NT_HEADERS, ldr_entry->dll_base,
            ((PIMAGE_DOS_HEADER)ldr_entry->dll_base)->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);

    for (INT i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
      if (!strcmp(".data", (LPCSTR)section->Name)) {
        begin = (SIZE_T)ldr_entry->dll_base + section->VirtualAddress;
        len = section->Misc.VirtualSize;
        break;
      }
      ++section;
    }

    for (DWORD i = 0; i < len - sizeof(SIZE_T); ++begin, ++i) {
      SIZE_T ret = RtlCompareMemory((PVOID)begin, (PVOID)&node, sizeof(SIZE_T));
      if (ret == sizeof(SIZE_T)) {
        end = begin;
        break;
      }
    }

    if (end == NULL) {
      return NULL;
    }

    PRTL_RB_TREE tree = (PRTL_RB_TREE)end;
    if (tree && tree->root && tree->min) {
      mod_base_addr_index = tree;
    }
  }
  return mod_base_addr_index;
}

// Computes a hash for a Unicode name entry.
ULONG LdrHashEntry(UNICODE_STRING uni_name, BOOL xor_hash) {
  ULONG result = 0;
  RtlHashUnicodeString(&uni_name, TRUE, 0, &result);
  if (xor_hash) {
    result &= (LDR_HASH_TABLE_ENTRIES - 1);
  }
  return result;
}

// Adds a base address entry to the module index.
BOOL AddBaseAddressEntry(InternalLdrDataTableEntry* ldr_entry,
                         PVOID base_addr) {
  PRTL_RB_TREE mod_base_addr_index = FindModuleBaseAddressIndex();
  if (!mod_base_addr_index) {
    return FALSE;
  }

  BOOL right = FALSE;
  InternalLdrDataTableEntry* ldr_node =
      (InternalLdrDataTableEntry*)((size_t)mod_base_addr_index -
                                   offsetof(InternalLdrDataTableEntry,
                                            base_address_index_node));

  do {
    if (base_addr < ldr_node->dll_base) {
      if (!ldr_node->base_address_index_node.left) {
        break;
      }
      ldr_node =
          (InternalLdrDataTableEntry*)((size_t)ldr_node->base_address_index_node
                                           .left -
                                       offsetof(InternalLdrDataTableEntry,
                                                base_address_index_node));
    } else if (base_addr > ldr_node->dll_base) {
      if (!ldr_node->base_address_index_node.right) {
        right = TRUE;
        break;
      }
      ldr_node =
          (InternalLdrDataTableEntry*)((size_t)ldr_node->base_address_index_node
                                           .right -
                                       offsetof(InternalLdrDataTableEntry,
                                                base_address_index_node));
    } else {
      ldr_node->ddag_node->load_count++;
    }
  } while (TRUE);

  RtlRbInsertNodeEx(mod_base_addr_index, &ldr_node->base_address_index_node,
                    right, &ldr_entry->base_address_index_node);
  return TRUE;
}

// Adds an entry to the hash table and PEB lists.
BOOL AddHashTableEntry(InternalLdrDataTableEntry* ldr_entry) {
  PInternalPeb peb;
  PLIST_ENTRY ldrp_hash_table;

  peb = (PInternalPeb)__readgsqword(0x60);
  RtlInitializeListEntry(&ldr_entry->hash_links);

  ldrp_hash_table = FindHashTable();
  if (!ldrp_hash_table) {
    return FALSE;
  }

  const ULONG hash = LdrHashEntry(ldr_entry->base_dll_name, TRUE);

  InsertTailList(&ldrp_hash_table[hash], &ldr_entry->hash_links);
  InsertTailList(&peb->ldr->in_load_order_module_list,
                 &ldr_entry->in_load_order_links);
  InsertTailList(&peb->ldr->in_memory_order_module_list,
                 &ldr_entry->in_memory_order_links);
  InsertTailList(&peb->ldr->in_initialization_order_module_list,
                 &ldr_entry->in_initialization_order_links);
  return TRUE;
}

// Enumerates the PEB module list.
template <typename TFn>
void EnumPebModuleList(TFn&& fn) {
  InternalPeb* peb;
  peb = (InternalPeb*)__readgsqword(0x60);
  PLIST_ENTRY list_head = &peb->ldr->in_load_order_module_list;
  PLIST_ENTRY list_entry = list_head->Flink;

  do {
    InternalLdrDataTableEntry* cur_entry = CONTAINING_RECORD(
        list_entry, InternalLdrDataTableEntry, in_load_order_links);
    list_entry = list_entry->Flink;
    fn(list_entry);
  } while (list_entry != list_head);
}

// Enumerates LDR table entries from the hash table.
template <typename TFn>
void EnumLdrTableEntries(TFn &&fn) {
  auto ldrp_hash_table = FindHashTable();
  if (!ldrp_hash_table) {
    return;
  }

  OutputDebugStringW(L"Enumerating LdrpHashTable entries:\n");

  for (int i = 0; i < LDR_HASH_TABLE_ENTRIES; ++i) {
    __try {
      PLIST_ENTRY list_entry = ldrp_hash_table[i].Flink;
      if (!list_entry) {
        continue;
      }
      if (list_entry != &ldrp_hash_table[i]) {
        wchar_t idx_msg[64];
        wsprintfW(idx_msg, L"Bucket %d:\n", i);
        OutputDebugStringW(idx_msg);
      }
      while (list_entry != &ldrp_hash_table[i]) {
        InternalLdrDataTableEntry* cur_entry = CONTAINING_RECORD(
            list_entry, InternalLdrDataTableEntry, hash_links);
        list_entry = list_entry->Flink;
        if (!fn(cur_entry)) return;
        if (cur_entry->base_dll_name.Buffer) {
          OutputDebugStringW(cur_entry->base_dll_name.Buffer);
          OutputDebugStringW(L"\n");
        }
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      continue;
    }
  }
}

// Inserts a module into the LDR module list.
void NtLoaderInsertModuleToModuleList(const NtLoaderModule* module) {
  UNICODE_STRING full_dll_name, base_dll_name;
  InternalLdrDataTableEntry* ldr_entry = NULL;

  PIMAGE_NT_HEADERS nt_headers =
      (PIMAGE_NT_HEADERS)NtLoaderGetBinaryNtHeader(*module);
  RtlInitUnicodeString(&full_dll_name, module->disk_path->Buffer);
  RtlInitUnicodeString(&base_dll_name, module->module_name->Buffer);

  ldr_entry = (InternalLdrDataTableEntry*)HeapAlloc(
      ::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(InternalLdrDataTableEntry));

  if (!ldr_entry) {
    return;
  }

  NtQuerySystemTime(&ldr_entry->load_time);
  ldr_entry->reference_count = 1;
  ldr_entry->load_reason = LoadReasonDynamicLoad;
  ldr_entry->original_base = nt_headers->OptionalHeader.ImageBase;
  ldr_entry->base_name_hash_value = LdrHashEntry(base_dll_name, FALSE);

  PVOID base_addr = module->module_handle;
  if (!AddBaseAddressEntry(ldr_entry, base_addr)) {
    HeapFree(GetProcessHeap(), 0, ldr_entry->ddag_node);
    HeapFree(GetProcessHeap(), 0, ldr_entry);
    return;
  }

  ldr_entry->image_dll = TRUE;
  ldr_entry->load_notifications_sent = TRUE;
  ldr_entry->entry_processed = TRUE;
  ldr_entry->in_legacy_lists = TRUE;
  ldr_entry->in_indexes = TRUE;
  ldr_entry->process_attach_called = TRUE;
  ldr_entry->in_exception_table = FALSE;
  ldr_entry->dll_base = base_addr;
  ldr_entry->size_of_image = nt_headers->OptionalHeader.SizeOfImage;
  ldr_entry->time_date_stamp = nt_headers->FileHeader.TimeDateStamp;
  ldr_entry->base_dll_name = base_dll_name;
  ldr_entry->full_dll_name = full_dll_name;
  ldr_entry->obsolete_load_count = 1;
  ldr_entry->flags = LDRP_IMAGE_DLL | LDRP_ENTRY_INSERTED |
                     LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED;

  ldr_entry->ddag_node = (PLDR_DDAG_NODE)::HeapAlloc(
      ::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LDR_DDAG_NODE));

  if (!ldr_entry->ddag_node) {
    return;
  }

  ldr_entry->node_module_link.Flink = &ldr_entry->ddag_node->modules;
  ldr_entry->node_module_link.Blink = &ldr_entry->ddag_node->modules;
  ldr_entry->ddag_node->modules.Flink = &ldr_entry->node_module_link;
  ldr_entry->ddag_node->modules.Blink = &ldr_entry->node_module_link;
  ldr_entry->ddag_node->state = LdrModulesReadyToRun;
  ldr_entry->ddag_node->load_count = 1;

  AddHashTableEntry(ldr_entry);
  ldr_entry->entry_point = RVA(PVOID, module->module_handle,
                               nt_headers->OptionalHeader.AddressOfEntryPoint);

 // EnumPebModuleList();
 // OutputDebugStringW(L"Inserted module to the list\n");
 // EnumLdrTableEntries();
}

void NtLoaderOverwriteInitialModule(const NtLoaderModule* module) {
  EnumLdrTableEntries([&](InternalLdrDataTableEntry* entry) {
    if (entry->dll_base == module->module_handle) {
      // Overwrite the entry with the new module information.
      entry->full_dll_name.Buffer = module->disk_path->Buffer;
      entry->full_dll_name.Length = module->disk_path->Length;
      entry->full_dll_name.MaximumLength = module->disk_path->MaximumLength;

      entry->base_dll_name.Buffer = module->module_name->Buffer;
      entry->base_dll_name.Length = module->module_name->Length;
      entry->base_dll_name.MaximumLength = module->module_name->MaximumLength;

      return TRUE;
    }
  });
}

#endif  // MODULE_LIST_H_
