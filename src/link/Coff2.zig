base: link.File,
mf: MappedFile,
nodes: std.MultiArrayList(Node),
import_table: ImportTable,
strings: std.HashMapUnmanaged(
    u32,
    void,
    std.hash_map.StringIndexContext,
    std.hash_map.default_max_load_percentage,
),
string_bytes: std.ArrayList(u8),
symtab: std.ArrayList(Symbol),
globals: std.AutoArrayHashMapUnmanaged(GlobalName, Symbol.Index),
global_pending_index: u32,
navs: std.AutoArrayHashMapUnmanaged(InternPool.Nav.Index, Symbol.Index),
uavs: std.AutoArrayHashMapUnmanaged(InternPool.Index, Symbol.Index),
lazy: std.EnumArray(link.File.LazySymbol.Kind, struct {
    map: std.AutoArrayHashMapUnmanaged(InternPool.Index, Symbol.Index),
    pending_index: u32,
}),
pending_uavs: std.AutoArrayHashMapUnmanaged(Node.UavMapIndex, struct {
    alignment: InternPool.Alignment,
    src_loc: Zcu.LazySrcLoc,
}),
relocs: std.ArrayList(Reloc),
/// This is hiding actual bugs with global symbols! Reconsider once they are implemented correctly.
entry_hack: Symbol.Index,

pub const Node = union(enum) {
    file,
    header,
    signature,
    coff_header,
    optional_header,
    data_directories,
    section_table,
    section: Symbol.Index,
    import_directory_table,
    import_lookup_table: u32,
    import_address_table: u32,
    import_hint_name_table: u32,
    global: GlobalMapIndex,
    nav: NavMapIndex,
    uav: UavMapIndex,
    lazy_code: LazyMapRef.Index(.code),
    lazy_const_data: LazyMapRef.Index(.const_data),

    pub const GlobalMapIndex = enum(u32) {
        _,

        pub fn globalName(gmi: GlobalMapIndex, coff: *const Coff) GlobalName {
            return coff.globals.keys()[@intFromEnum(gmi)];
        }

        pub fn symbolIndex(gmi: GlobalMapIndex, coff: *const Coff) Symbol.Index {
            return coff.globals.values()[@intFromEnum(gmi)];
        }
    };

    pub const NavMapIndex = enum(u32) {
        _,

        pub fn navIndex(nmi: NavMapIndex, coff: *const Coff) InternPool.Nav.Index {
            return coff.navs.keys()[@intFromEnum(nmi)];
        }

        pub fn symbolIndex(nmi: NavMapIndex, coff: *const Coff) Symbol.Index {
            return coff.navs.values()[@intFromEnum(nmi)];
        }
    };

    pub const UavMapIndex = enum(u32) {
        _,

        pub fn uavValue(umi: UavMapIndex, coff: *const Coff) InternPool.Index {
            return coff.uavs.keys()[@intFromEnum(umi)];
        }

        pub fn symbolIndex(umi: UavMapIndex, coff: *const Coff) Symbol.Index {
            return coff.uavs.values()[@intFromEnum(umi)];
        }
    };

    pub const LazyMapRef = struct {
        kind: link.File.LazySymbol.Kind,
        index: u32,

        pub fn Index(comptime kind: link.File.LazySymbol.Kind) type {
            return enum(u32) {
                _,

                pub fn ref(lmi: @This()) LazyMapRef {
                    return .{ .kind = kind, .index = @intFromEnum(lmi) };
                }

                pub fn lazySymbol(lmi: @This(), coff: *const Coff) link.File.LazySymbol {
                    return lmi.ref().lazySymbol(coff);
                }

                pub fn symbolIndex(lmi: @This(), coff: *const Coff) Symbol.Index {
                    return lmi.ref().symbolIndex(coff);
                }
            };
        }

        pub fn lazySymbol(lmr: LazyMapRef, coff: *const Coff) link.File.LazySymbol {
            return .{ .kind = lmr.kind, .ty = coff.lazy.getPtrConst(lmr.kind).map.keys()[lmr.index] };
        }

        pub fn symbolIndex(lmr: LazyMapRef, coff: *const Coff) Symbol.Index {
            return coff.lazy.getPtrConst(lmr.kind).map.values()[lmr.index];
        }
    };

    pub const Tag = @typeInfo(Node).@"union".tag_type.?;

    const known_count = @typeInfo(@TypeOf(known)).@"struct".fields.len;
    const known = known: {
        const Known = enum {
            file,
            header,
            signature,
            coff_header,
            optional_header,
            data_directories,
            section_table,
        };
        var mut_known: std.enums.EnumFieldStruct(Known, MappedFile.Node.Index, null) = undefined;
        for (@typeInfo(Known).@"enum".fields) |field|
            @field(mut_known, field.name) = @enumFromInt(field.value);
        break :known mut_known;
    };

    comptime {
        if (!std.debug.runtime_safety) std.debug.assert(@sizeOf(Node) == 8);
    }
};

pub const DataDirectory = enum {
    export_table,
    import_table,
    resorce_table,
    exception_table,
    certificate_table,
    base_relocation_table,
    debug,
    architecture,
    global_ptr,
    tls_table,
    load_config_table,
    bound_import,
    import_address_table,
    delay_import_descriptor,
    clr_runtime_header,
    reserved,
};

pub const ImportTable = struct {
    directory_table_ni: MappedFile.Node.Index,
    dlls: std.AutoArrayHashMapUnmanaged(void, Dll),

    pub const Dll = struct {
        import_lookup_table_ni: MappedFile.Node.Index,
        import_address_table_si: Symbol.Index,
        import_hint_name_table_ni: MappedFile.Node.Index,
        len: u32,
        hint_name_len: u32,
    };

    const Adapter = struct {
        coff: *Coff,

        pub fn eql(adapter: Adapter, lhs_key: []const u8, _: void, rhs_index: usize) bool {
            const coff = adapter.coff;
            const dll_name = coff.import_table.dlls.values()[rhs_index]
                .import_hint_name_table_ni.sliceConst(&coff.mf);
            return std.mem.startsWith(u8, dll_name, lhs_key) and
                std.mem.startsWith(u8, dll_name[lhs_key.len..], ".dll\x00");
        }

        pub fn hash(_: Adapter, key: []const u8) u32 {
            assert(std.mem.indexOfScalar(u8, key, 0) == null);
            return std.array_hash_map.hashString(key);
        }
    };
};

pub const String = enum(u32) {
    _,

    pub const Optional = enum(u32) {
        none = std.math.maxInt(u32),
        _,

        pub fn unwrap(os: String.Optional) ?String {
            return switch (os) {
                else => |s| @enumFromInt(@intFromEnum(s)),
                .none => null,
            };
        }

        pub fn toSlice(os: String.Optional, coff: *Coff) ?[:0]const u8 {
            return (os.unwrap() orelse return null).toSlice(coff);
        }
    };

    pub fn toSlice(s: String, coff: *Coff) [:0]const u8 {
        const slice = coff.string_bytes.items[@intFromEnum(s)..];
        return slice[0..std.mem.indexOfScalar(u8, slice, 0).? :0];
    }

    pub fn toOptional(s: String) String.Optional {
        return @enumFromInt(@intFromEnum(s));
    }
};

pub const GlobalName = struct { name: String, lib_name: String.Optional };

pub const Symbol = struct {
    ni: MappedFile.Node.Index,
    rva: u32,
    size: u32,
    /// Relocations contained within this symbol
    loc_relocs: Reloc.Index,
    /// Relocations targeting this symbol
    target_relocs: Reloc.Index,
    section_number: SectionNumber,
    data_directory: ?DataDirectory,
    unused0: u32 = 0,
    unused1: u32 = 0,

    pub const SectionNumber = enum(i16) {
        UNDEFINED = 0,
        ABSOLUTE = -1,
        DEBUG = -2,
        _,

        pub fn get(sn: SectionNumber, coff: *Coff) *std.coff.SectionHeader {
            return &coff.sectionTableSlice()[@intCast(@intFromEnum(sn) - 1)];
        }
    };

    pub const Index = enum(u32) {
        null,
        data,
        idata,
        rdata,
        text,
        _,

        const known_count = @typeInfo(Index).@"enum".fields.len;

        pub fn get(si: Symbol.Index, coff: *Coff) *Symbol {
            return &coff.symtab.items[@intFromEnum(si)];
        }

        pub fn node(si: Symbol.Index, coff: *Coff) MappedFile.Node.Index {
            const ni = si.get(coff).ni;
            assert(ni != .none);
            return ni;
        }

        pub fn flushMoved(si: Symbol.Index, coff: *Coff, file_offset: u64) void {
            const target_endian = coff.endian();
            const sym = si.get(coff);
            const sec = sym.section_number.get(coff);
            const sec_rva =
                std.mem.toNative(@TypeOf(sec.virtual_address), sec.virtual_address, target_endian);
            const sec_file_offset = std.mem.toNative(
                @TypeOf(sec.pointer_to_raw_data),
                sec.pointer_to_raw_data,
                target_endian,
            );
            sym.rva = @intCast(file_offset - sec_file_offset + sec_rva);
            if (si == coff.entry_hack) switch (coff.optionalHeaderPtr()) {
                inline else => |header| header.address_of_entry_point = std.mem.nativeTo(
                    @TypeOf(header.address_of_entry_point),
                    @intCast(sym.rva),
                    target_endian,
                ),
            };
            si.applyLocationRelocs(coff);
            si.applyTargetRelocs(coff);
        }

        pub fn applyLocationRelocs(si: Symbol.Index, coff: *Coff) void {
            for (coff.relocs.items[@intFromEnum(si.get(coff).loc_relocs)..]) |*reloc| {
                if (reloc.loc != si) break;
                reloc.apply(coff);
            }
        }

        pub fn applyTargetRelocs(si: Symbol.Index, coff: *Coff) void {
            var ri = si.get(coff).target_relocs;
            while (ri != .none) {
                const reloc = ri.get(coff);
                assert(reloc.target == si);
                reloc.apply(coff);
                ri = reloc.next;
            }
        }

        pub fn deleteLocationRelocs(si: Symbol.Index, coff: *Coff) void {
            const sym = si.get(coff);
            for (coff.relocs.items[@intFromEnum(sym.loc_relocs)..]) |*reloc| {
                if (reloc.loc != si) break;
                reloc.delete(coff);
            }
            sym.loc_relocs = .none;
        }
    };

    comptime {
        if (!std.debug.runtime_safety) std.debug.assert(@sizeOf(Symbol) == 32);
    }
};

pub const Reloc = extern struct {
    type: Reloc.Type,
    prev: Reloc.Index,
    next: Reloc.Index,
    loc: Symbol.Index,
    target: Symbol.Index,
    unused: u32,
    offset: u64,
    addend: i64,

    pub const Type = extern union {
        AMD64: std.coff.IMAGE.REL.AMD64,
        ARM: std.coff.IMAGE.REL.ARM,
        ARM64: std.coff.IMAGE.REL.ARM64,
        SH: std.coff.IMAGE.REL.SH,
        PPC: std.coff.IMAGE.REL.PPC,
        I386: std.coff.IMAGE.REL.I386,
        IA64: std.coff.IMAGE.REL.IA64,
        MIPS: std.coff.IMAGE.REL.MIPS,
        M32R: std.coff.IMAGE.REL.M32R,
    };

    pub const Index = enum(u32) {
        none = std.math.maxInt(u32),
        _,

        pub fn get(si: Reloc.Index, coff: *Coff) *Reloc {
            return &coff.relocs.items[@intFromEnum(si)];
        }
    };

    pub fn apply(reloc: *const Reloc, coff: *Coff) void {
        const target_endian = coff.endian();
        const loc_sym = reloc.loc.get(coff);
        switch (loc_sym.ni) {
            .none => return,
            else => |ni| if (ni.hasMoved(&coff.mf)) return,
        }
        const target_sym = reloc.target.get(coff);
        switch (target_sym.ni) {
            .none => return,
            else => |ni| if (ni.hasMoved(&coff.mf)) return,
        }
        const loc_rva = loc_sym.rva + reloc.offset;
        const loc_sec = loc_sym.section_number.get(coff);
        const loc_sec_rva =
            std.mem.toNative(@TypeOf(loc_sec.virtual_address), loc_sec.virtual_address, target_endian);
        const loc_sec_file_offset = std.mem.toNative(
            @TypeOf(loc_sec.pointer_to_raw_data),
            loc_sec.pointer_to_raw_data,
            target_endian,
        );
        const loc_file_offset: usize = @intCast(loc_rva - loc_sec_rva + loc_sec_file_offset);
        const target_rva = target_sym.rva +% @as(u64, @bitCast(reloc.addend));
        switch (coff.headerField(.machine)) {
            else => |machine| @panic(@tagName(machine)),
            .AMD64 => switch (reloc.type.AMD64) {
                else => |kind| @panic(@tagName(kind)),
                .ABSOLUTE => {},
                .ADDR64 => std.mem.writeInt(
                    u64,
                    coff.mf.contents[loc_file_offset..][0..8],
                    coff.baseAddr() + target_rva,
                    target_endian,
                ),
                .ADDR32 => std.mem.writeInt(
                    u32,
                    coff.mf.contents[loc_file_offset..][0..4],
                    @intCast(coff.baseAddr() + target_rva),
                    target_endian,
                ),
                .ADDR32NB => std.mem.writeInt(
                    u32,
                    coff.mf.contents[loc_file_offset..][0..4],
                    @intCast(target_rva),
                    target_endian,
                ),
                .REL32 => std.mem.writeInt(
                    i32,
                    coff.mf.contents[loc_file_offset..][0..4],
                    @intCast(@as(i64, @bitCast(target_rva -% loc_rva -% 4))),
                    target_endian,
                ),
                .REL32_1 => std.mem.writeInt(
                    i32,
                    coff.mf.contents[loc_file_offset..][0..4],
                    @intCast(@as(i64, @bitCast(target_rva -% loc_rva -% 5))),
                    target_endian,
                ),
                .REL32_2 => std.mem.writeInt(
                    i32,
                    coff.mf.contents[loc_file_offset..][0..4],
                    @intCast(@as(i64, @bitCast(target_rva -% loc_rva -% 6))),
                    target_endian,
                ),
                .REL32_3 => std.mem.writeInt(
                    i32,
                    coff.mf.contents[loc_file_offset..][0..4],
                    @intCast(@as(i64, @bitCast(target_rva -% loc_rva -% 7))),
                    target_endian,
                ),
                .REL32_4 => std.mem.writeInt(
                    i32,
                    coff.mf.contents[loc_file_offset..][0..4],
                    @intCast(@as(i64, @bitCast(target_rva -% loc_rva -% 8))),
                    target_endian,
                ),
                .REL32_5 => std.mem.writeInt(
                    i32,
                    coff.mf.contents[loc_file_offset..][0..4],
                    @intCast(@as(i64, @bitCast(target_rva -% loc_rva -% 9))),
                    target_endian,
                ),
            },
            .I386 => switch (reloc.type.I386) {
                else => |kind| @panic(@tagName(kind)),
                .ABSOLUTE => {},
                .DIR16 => std.mem.writeInt(
                    u16,
                    coff.mf.contents[loc_file_offset..][0..2],
                    @intCast(coff.baseAddr() + target_rva),
                    target_endian,
                ),
                .REL16 => std.mem.writeInt(
                    i16,
                    coff.mf.contents[loc_file_offset..][0..2],
                    @intCast(@as(i64, @bitCast(target_rva -% loc_rva -% 2))),
                    target_endian,
                ),
                .DIR32 => std.mem.writeInt(
                    u32,
                    coff.mf.contents[loc_file_offset..][0..4],
                    @intCast(coff.baseAddr() + target_rva),
                    target_endian,
                ),
                .DIR32NB => std.mem.writeInt(
                    u32,
                    coff.mf.contents[loc_file_offset..][0..4],
                    @intCast(target_rva),
                    target_endian,
                ),
                .REL32 => std.mem.writeInt(
                    i32,
                    coff.mf.contents[loc_file_offset..][0..4],
                    @intCast(@as(i64, @bitCast(target_rva -% loc_rva -% 4))),
                    target_endian,
                ),
            },
        }
    }

    pub fn delete(reloc: *Reloc, coff: *Coff) void {
        switch (reloc.prev) {
            .none => {
                const target = reloc.target.get(coff);
                assert(target.target_relocs.get(coff) == reloc);
                target.target_relocs = reloc.next;
            },
            else => |prev| prev.get(coff).next = reloc.next,
        }
        switch (reloc.next) {
            .none => {},
            else => |next| next.get(coff).prev = reloc.prev,
        }
        reloc.* = undefined;
    }

    comptime {
        if (!std.debug.runtime_safety) std.debug.assert(@sizeOf(Reloc) == 40);
    }
};

pub fn open(
    arena: std.mem.Allocator,
    comp: *Compilation,
    path: std.Build.Cache.Path,
    options: link.File.OpenOptions,
) !*Coff {
    return create(arena, comp, path, options);
}
pub fn createEmpty(
    arena: std.mem.Allocator,
    comp: *Compilation,
    path: std.Build.Cache.Path,
    options: link.File.OpenOptions,
) !*Coff {
    return create(arena, comp, path, options);
}
fn create(
    arena: std.mem.Allocator,
    comp: *Compilation,
    path: std.Build.Cache.Path,
    options: link.File.OpenOptions,
) !*Coff {
    const target = &comp.root_mod.resolved_target.result;
    assert(target.ofmt == .coff);
    const is_image = switch (comp.config.output_mode) {
        .Exe => true,
        .Lib => switch (comp.config.link_mode) {
            .static => false,
            .dynamic => true,
        },
        .Obj => false,
    };
    const machine = target.toCoffMachine();
    const timestamp: u32 = if (options.repro) 0 else @truncate(@as(u64, @bitCast(std.time.timestamp())));
    const major_subsystem_version = options.major_subsystem_version orelse 6;
    const minor_subsystem_version = options.minor_subsystem_version orelse 0;
    const magic: std.coff.OptionalHeader.Magic = switch (target.ptrBitWidth()) {
        0...32 => .PE32,
        33...64 => .@"PE32+",
        else => return error.UnsupportedCOFFArchitecture,
    };

    const coff = try arena.create(Coff);
    const file = try path.root_dir.handle.createFile(path.sub_path, .{
        .read = true,
        .mode = link.File.determineMode(comp.config.output_mode, comp.config.link_mode),
    });
    errdefer file.close();
    coff.* = .{
        .base = .{
            .tag = .coff2,

            .comp = comp,
            .emit = path,

            .file = file,
            .gc_sections = false,
            .print_gc_sections = false,
            .build_id = .none,
            .allow_shlib_undefined = false,
            .stack_size = 0,
        },
        .mf = try .init(file, comp.gpa),
        .nodes = .empty,
        .import_table = .{
            .directory_table_ni = .none,
            .dlls = .empty,
        },
        .strings = .empty,
        .string_bytes = .empty,
        .symtab = .empty,
        .globals = .empty,
        .global_pending_index = 0,
        .navs = .empty,
        .uavs = .empty,
        .lazy = .initFill(.{
            .map = .empty,
            .pending_index = 0,
        }),
        .pending_uavs = .empty,
        .relocs = .empty,
        .entry_hack = .null,
    };
    errdefer coff.deinit();

    try coff.initHeaders(
        is_image,
        machine,
        timestamp,
        major_subsystem_version,
        minor_subsystem_version,
        magic,
    );
    return coff;
}

pub fn deinit(coff: *Coff) void {
    const gpa = coff.base.comp.gpa;
    coff.mf.deinit(gpa);
    coff.nodes.deinit(gpa);
    coff.import_table.dlls.deinit(gpa);
    coff.strings.deinit(gpa);
    coff.string_bytes.deinit(gpa);
    coff.symtab.deinit(gpa);
    coff.globals.deinit(gpa);
    coff.navs.deinit(gpa);
    coff.uavs.deinit(gpa);
    for (&coff.lazy.values) |*lazy| lazy.map.deinit(gpa);
    coff.pending_uavs.deinit(gpa);
    coff.relocs.deinit(gpa);
    coff.* = undefined;
}

fn initHeaders(
    coff: *Coff,
    is_image: bool,
    machine: std.coff.IMAGE.FILE.MACHINE,
    timestamp: u32,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    magic: std.coff.OptionalHeader.Magic,
) !void {
    const comp = coff.base.comp;
    const gpa = comp.gpa;
    const file_align: std.mem.Alignment =
        comptime .fromByteUnits(link.File.Coff.default_file_alignment);
    const target_endian = coff.endian();

    const optional_header_size: u16 = if (is_image) switch (magic) {
        _ => unreachable,
        .PE32 => @sizeOf(std.coff.OptionalHeaderPE32),
        .@"PE32+" => @sizeOf(std.coff.OptionalHeaderPE64),
    } else 0;
    const data_directories_len = @typeInfo(DataDirectory).@"enum".fields.len;
    const data_directories_size: u16 = if (is_image)
        @sizeOf(std.coff.ImageDataDirectory) * data_directories_len
    else
        0;

    try coff.nodes.ensureTotalCapacity(gpa, Node.known_count);
    coff.nodes.appendAssumeCapacity(.file);

    const header_ni = Node.known.header;
    assert(header_ni == try coff.mf.addOnlyChildNode(gpa, .root, .{
        .alignment = coff.mf.flags.block_size,
        .fixed = true,
        .moved = true,
    }));
    coff.nodes.appendAssumeCapacity(.header);

    const signature_ni = Node.known.signature;
    assert(signature_ni == try coff.mf.addOnlyChildNode(gpa, header_ni, .{
        .size = (if (is_image) link.File.Coff.msdos_stub.len else 0) + "PE\x00\x00".len,
        .alignment = .@"4",
        .fixed = true,
        .moved = true,
    }));
    coff.nodes.appendAssumeCapacity(.signature);
    {
        const signature_slice = signature_ni.slice(&coff.mf);
        if (is_image)
            @memcpy(signature_slice[0..link.File.Coff.msdos_stub.len], &link.File.Coff.msdos_stub);
        @memcpy(signature_slice[signature_slice.len - 4 ..], "PE\x00\x00");
    }

    const coff_header_ni = Node.known.coff_header;
    assert(coff_header_ni == try coff.mf.addLastChildNode(gpa, header_ni, .{
        .size = @sizeOf(std.coff.Header),
        .alignment = .@"4",
        .fixed = true,
        .moved = true,
    }));
    coff.nodes.appendAssumeCapacity(.coff_header);
    {
        const coff_header: *std.coff.Header = @ptrCast(@alignCast(coff_header_ni.slice(&coff.mf)));
        coff_header.* = .{
            .machine = machine,
            .number_of_sections = 0,
            .time_date_stamp = timestamp,
            .pointer_to_symbol_table = 0,
            .number_of_symbols = 0,
            .size_of_optional_header = optional_header_size + data_directories_size,
            .flags = .{
                .RELOCS_STRIPPED = is_image,
                .EXECUTABLE_IMAGE = is_image,
                .DEBUG_STRIPPED = true,
                .@"32BIT_MACHINE" = magic == .PE32,
                .LARGE_ADDRESS_AWARE = magic == .@"PE32+",
                .DLL = comp.config.output_mode == .Lib and comp.config.link_mode == .dynamic,
            },
        };
        if (target_endian != native_endian) std.mem.byteSwapAllFields(std.coff.Header, coff_header);
    }

    const optional_header_ni = Node.known.optional_header;
    assert(optional_header_ni == try coff.mf.addLastChildNode(gpa, header_ni, .{
        .size = optional_header_size,
        .alignment = .@"4",
        .fixed = true,
        .moved = true,
    }));
    coff.nodes.appendAssumeCapacity(.optional_header);

    if (is_image) switch (magic) {
        _ => unreachable,
        .PE32 => {
            const optional_header: *std.coff.OptionalHeaderPE32 =
                @ptrCast(@alignCast(optional_header_ni.slice(&coff.mf)));
            optional_header.* = .{
                .magic = .PE32,
                .major_linker_version = 0,
                .minor_linker_version = 0,
                .size_of_code = 0,
                .size_of_initialized_data = 0,
                .size_of_uninitialized_data = 0,
                .address_of_entry_point = 0,
                .base_of_code = 0,
                .base_of_data = 0,
                .image_base = @intCast(coff.baseAddr()),
                .section_alignment = 0x1000,
                .file_alignment = @intCast(file_align.toByteUnits()),
                .major_operating_system_version = 6,
                .minor_operating_system_version = 0,
                .major_image_version = 0,
                .minor_image_version = 0,
                .major_subsystem_version = major_subsystem_version,
                .minor_subsystem_version = minor_subsystem_version,
                .win32_version_value = 0,
                .size_of_image = 0,
                .size_of_headers = 0,
                .checksum = 0,
                .subsystem = .WINDOWS_CUI,
                .dll_flags = .{
                    .HIGH_ENTROPY_VA = true,
                    .DYNAMIC_BASE = true,
                    .TERMINAL_SERVER_AWARE = true,
                    .NX_COMPAT = true,
                },
                .size_of_stack_reserve = link.File.Coff.default_size_of_stack_reserve,
                .size_of_stack_commit = link.File.Coff.default_size_of_stack_commit,
                .size_of_heap_reserve = link.File.Coff.default_size_of_heap_reserve,
                .size_of_heap_commit = link.File.Coff.default_size_of_heap_commit,
                .loader_flags = 0,
                .number_of_rva_and_sizes = data_directories_len,
            };
            if (target_endian != native_endian)
                std.mem.byteSwapAllFields(std.coff.OptionalHeaderPE32, optional_header);
        },
        .@"PE32+" => {
            const header: *std.coff.OptionalHeaderPE64 =
                @ptrCast(@alignCast(optional_header_ni.slice(&coff.mf)));
            header.* = .{
                .magic = .@"PE32+",
                .major_linker_version = 0,
                .minor_linker_version = 0,
                .size_of_code = 0,
                .size_of_initialized_data = 0,
                .size_of_uninitialized_data = 0,
                .address_of_entry_point = 0,
                .base_of_code = 0,
                .image_base = coff.baseAddr(),
                .section_alignment = 0x1000,
                .file_alignment = @intCast(file_align.toByteUnits()),
                .major_operating_system_version = 6,
                .minor_operating_system_version = 0,
                .major_image_version = 0,
                .minor_image_version = 0,
                .major_subsystem_version = major_subsystem_version,
                .minor_subsystem_version = minor_subsystem_version,
                .win32_version_value = 0,
                .size_of_image = 0,
                .size_of_headers = 0,
                .checksum = 0,
                .subsystem = .WINDOWS_CUI,
                .dll_flags = .{
                    .HIGH_ENTROPY_VA = true,
                    .DYNAMIC_BASE = true,
                    .TERMINAL_SERVER_AWARE = true,
                    .NX_COMPAT = true,
                },
                .size_of_stack_reserve = link.File.Coff.default_size_of_stack_reserve,
                .size_of_stack_commit = link.File.Coff.default_size_of_stack_commit,
                .size_of_heap_reserve = link.File.Coff.default_size_of_heap_reserve,
                .size_of_heap_commit = link.File.Coff.default_size_of_heap_commit,
                .loader_flags = 0,
                .number_of_rva_and_sizes = data_directories_len,
            };
            if (target_endian != native_endian)
                std.mem.byteSwapAllFields(std.coff.OptionalHeaderPE64, header);
        },
    };

    const data_directories_ni = Node.known.data_directories;
    assert(data_directories_ni == try coff.mf.addLastChildNode(gpa, header_ni, .{
        .size = data_directories_size,
        .alignment = .@"4",
        .fixed = true,
        .moved = true,
    }));
    coff.nodes.appendAssumeCapacity(.data_directories);
    {
        const data_directories: *[data_directories_len]std.coff.ImageDataDirectory =
            @ptrCast(@alignCast(data_directories_ni.slice(&coff.mf)));
        data_directories[0] = .{
            .virtual_address = 0,
            .size = 0,
        };
        if (target_endian != native_endian)
            std.mem.byteSwapAllFields(std.coff.ImageDataDirectory, &data_directories[0]);
        data_directories[1] = .{
            .virtual_address = 0,
            .size = 0,
        };
        if (target_endian != native_endian)
            std.mem.byteSwapAllFields(std.coff.ImageDataDirectory, &data_directories[1]);
    }

    const section_table_ni = Node.known.section_table;
    assert(section_table_ni == try coff.mf.addLastChildNode(gpa, header_ni, .{
        .alignment = .@"4",
        .fixed = true,
        .moved = true,
    }));
    coff.nodes.appendAssumeCapacity(.section_table);

    assert(coff.nodes.len == Node.known_count);

    try coff.symtab.ensureTotalCapacity(gpa, Symbol.Index.known_count);
    coff.symtab.addOneAssumeCapacity().* = .{
        .ni = .none,
        .rva = 0,
        .size = 0,
        .loc_relocs = .none,
        .target_relocs = .none,
        .section_number = .UNDEFINED,
        .data_directory = null,
    };
    assert(try coff.addSection(".data", null, .{
        .CNT_INITIALIZED_DATA = true,
        .MEM_READ = true,
        .MEM_WRITE = true,
    }) == .data);
    assert(try coff.addSection(".idata", .import_table, .{
        .CNT_INITIALIZED_DATA = true,
        .MEM_READ = true,
    }) == .idata);
    assert(try coff.addSection(".rdata", null, .{
        .CNT_INITIALIZED_DATA = true,
        .MEM_READ = true,
    }) == .rdata);
    assert(try coff.addSection(".text", null, .{
        .CNT_CODE = true,
        .MEM_EXECUTE = true,
        .MEM_READ = true,
    }) == .text);
    coff.import_table.directory_table_ni = try coff.mf.addLastChildNode(
        gpa,
        Symbol.Index.idata.node(coff),
        .{
            .alignment = .@"4",
            .fixed = true,
        },
    );
    coff.nodes.appendAssumeCapacity(.import_directory_table);
    assert(coff.symtab.items.len == Symbol.Index.known_count);
}

fn getNode(coff: *Coff, ni: MappedFile.Node.Index) Node {
    return coff.nodes.get(@intFromEnum(ni));
}

pub inline fn endian(_: *Coff) std.builtin.Endian {
    return .little;
}

pub fn headerPtr(coff: *Coff) *std.coff.Header {
    return @ptrCast(@alignCast(Node.known.coff_header.slice(&coff.mf)));
}
pub fn headerField(
    coff: *Coff,
    comptime field: enum { machine },
) @FieldType(std.coff.Header, @tagName(field)) {
    return @enumFromInt(std.mem.toNative(
        @typeInfo(@FieldType(std.coff.Header, @tagName(field))).@"enum".tag_type,
        @intFromEnum(@field(coff.headerPtr(), @tagName(field))),
        coff.endian(),
    ));
}

pub fn optionalHeaderMagic(coff: *Coff) std.coff.OptionalHeader.Magic {
    const slice = Node.known.optional_header.slice(&coff.mf);
    const header: *std.coff.OptionalHeader =
        @ptrCast(@alignCast(slice[0..@sizeOf(std.coff.OptionalHeader)]));
    return @enumFromInt(std.mem.toNative(
        @typeInfo(std.coff.OptionalHeader.Magic).@"enum".tag_type,
        @intFromEnum(header.magic),
        coff.endian(),
    ));
}

pub const OptionalHeaderPtr = union(std.coff.OptionalHeader.Magic) {
    PE32: *std.coff.OptionalHeaderPE32,
    @"PE32+": *std.coff.OptionalHeaderPE64,
};
pub fn optionalHeaderPtr(coff: *Coff) OptionalHeaderPtr {
    const slice = Node.known.optional_header.slice(&coff.mf);
    return switch (coff.optionalHeaderMagic()) {
        _ => unreachable,
        inline else => |magic| @unionInit(
            OptionalHeaderPtr,
            @tagName(magic),
            @ptrCast(@alignCast(slice)),
        ),
    };
}

pub fn baseAddr(coff: *Coff) u64 {
    return switch (coff.base.comp.config.output_mode) {
        .Exe => switch (coff.optionalHeaderMagic()) {
            _ => unreachable,
            .PE32 => 0x400000,
            .@"PE32+" => 0x140000000,
        },
        .Lib => switch (coff.base.comp.config.link_mode) {
            .static => 0,
            .dynamic => switch (coff.optionalHeaderMagic()) {
                _ => unreachable,
                .PE32 => 0x10000000,
                .@"PE32+" => 0x180000000,
            },
        },
        .Obj => 0,
    };
}

pub fn dataDirectoriesSlice(coff: *Coff) []std.coff.ImageDataDirectory {
    return @ptrCast(@alignCast(Node.known.data_directories.slice(&coff.mf)));
}

pub fn sectionTableSlice(coff: *Coff) []std.coff.SectionHeader {
    return @ptrCast(@alignCast(Node.known.section_table.slice(&coff.mf)));
}

fn addSymbolAssumeCapacity(coff: *Coff) Symbol.Index {
    defer coff.symtab.addOneAssumeCapacity().* = .{
        .ni = .none,
        .rva = 0,
        .size = 0,
        .loc_relocs = .none,
        .target_relocs = .none,
        .section_number = .UNDEFINED,
        .data_directory = null,
    };
    return @enumFromInt(coff.symtab.items.len);
}

fn initSymbolAssumeCapacity(coff: *Coff) !Symbol.Index {
    const si = coff.addSymbolAssumeCapacity();
    return si;
}

fn getOrPutString(coff: *Coff, string: []const u8) !String {
    const gpa = coff.base.comp.gpa;
    try coff.string_bytes.ensureUnusedCapacity(gpa, string.len + 1);
    const gop = try coff.strings.getOrPutContextAdapted(
        gpa,
        string,
        std.hash_map.StringIndexAdapter{ .bytes = &coff.string_bytes },
        .{ .bytes = &coff.string_bytes },
    );
    if (!gop.found_existing) {
        gop.key_ptr.* = @intCast(coff.string_bytes.items.len);
        gop.value_ptr.* = {};
        coff.string_bytes.appendSliceAssumeCapacity(string);
        coff.string_bytes.appendAssumeCapacity(0);
    }
    return @enumFromInt(gop.key_ptr.*);
}

fn getOrPutOptionalString(coff: *Coff, string: ?[]const u8) !String.Optional {
    return (try coff.getOrPutString(string orelse return .none)).toOptional();
}

pub fn globalSymbol(coff: *Coff, name: []const u8, lib_name: ?[]const u8) !Symbol.Index {
    const gpa = coff.base.comp.gpa;
    try coff.symtab.ensureUnusedCapacity(gpa, 1);
    const sym_gop = try coff.globals.getOrPut(gpa, .{
        .name = try coff.getOrPutString(name),
        .lib_name = try coff.getOrPutOptionalString(lib_name),
    });
    if (!sym_gop.found_existing) {
        sym_gop.value_ptr.* = coff.addSymbolAssumeCapacity();
        coff.base.comp.link_synth_prog_node.increaseEstimatedTotalItems(1);
    }
    return sym_gop.value_ptr.*;
}

fn navMapIndex(coff: *Coff, zcu: *Zcu, nav_index: InternPool.Nav.Index) !Node.NavMapIndex {
    const gpa = zcu.gpa;
    try coff.symtab.ensureUnusedCapacity(gpa, 1);
    const sym_gop = try coff.navs.getOrPut(gpa, nav_index);
    if (!sym_gop.found_existing) sym_gop.value_ptr.* = coff.addSymbolAssumeCapacity();
    return @enumFromInt(sym_gop.index);
}
pub fn navSymbol(coff: *Coff, zcu: *Zcu, nav_index: InternPool.Nav.Index) !Symbol.Index {
    const ip = &zcu.intern_pool;
    const nav = ip.getNav(nav_index);
    if (nav.getExtern(ip)) |@"extern"| return coff.globalSymbol(
        @"extern".name.toSlice(ip),
        @"extern".lib_name.toSlice(ip),
    );
    const nmi = try coff.navMapIndex(zcu, nav_index);
    return nmi.symbolIndex(coff);
}

fn uavMapIndex(coff: *Coff, uav_val: InternPool.Index) !Node.UavMapIndex {
    const gpa = coff.base.comp.gpa;
    try coff.symtab.ensureUnusedCapacity(gpa, 1);
    const sym_gop = try coff.uavs.getOrPut(gpa, uav_val);
    if (!sym_gop.found_existing) sym_gop.value_ptr.* = coff.addSymbolAssumeCapacity();
    return @enumFromInt(sym_gop.index);
}
pub fn uavSymbol(coff: *Coff, uav_val: InternPool.Index) !Symbol.Index {
    const umi = try coff.uavMapIndex(uav_val);
    return umi.symbolIndex(coff);
}

pub fn lazySymbol(coff: *Coff, lazy: link.File.LazySymbol) !Symbol.Index {
    const gpa = coff.base.comp.gpa;
    try coff.symtab.ensureUnusedCapacity(gpa, 1);
    const sym_gop = try coff.lazy.getPtr(lazy.kind).map.getOrPut(gpa, lazy.ty);
    if (!sym_gop.found_existing) {
        sym_gop.value_ptr.* = try coff.initSymbolAssumeCapacity();
        coff.base.comp.link_synth_prog_node.increaseEstimatedTotalItems(1);
    }
    return sym_gop.value_ptr.*;
}

pub fn getNavVAddr(
    coff: *Coff,
    pt: Zcu.PerThread,
    nav: InternPool.Nav.Index,
    reloc_info: link.File.RelocInfo,
) !u64 {
    return coff.getVAddr(reloc_info, try coff.navSymbol(pt.zcu, nav));
}

pub fn getUavVAddr(
    coff: *Coff,
    uav: InternPool.Index,
    reloc_info: link.File.RelocInfo,
) !u64 {
    return coff.getVAddr(reloc_info, try coff.uavSymbol(uav));
}

pub fn getVAddr(coff: *Coff, reloc_info: link.File.RelocInfo, target_si: Symbol.Index) !u64 {
    try coff.addReloc(
        @enumFromInt(reloc_info.parent.atom_index),
        reloc_info.offset,
        target_si,
        reloc_info.addend,
        switch (coff.headerField(.machine)) {
            else => unreachable,
            .AMD64 => .{ .AMD64 = .ADDR64 },
            .I386 => .{ .I386 = .DIR32 },
        },
    );
    return 0;
}

fn addSection(
    coff: *Coff,
    name: []const u8,
    data_directory: ?DataDirectory,
    flags: std.coff.SectionHeader.Flags,
) !Symbol.Index {
    const gpa = coff.base.comp.gpa;
    const target_endian = coff.endian();
    try coff.nodes.ensureUnusedCapacity(gpa, 1);
    try coff.symtab.ensureUnusedCapacity(gpa, 1);

    const coff_header = coff.headerPtr();
    const section_index = std.mem.toNative(
        @TypeOf(coff_header.number_of_sections),
        coff_header.number_of_sections,
        target_endian,
    );
    const section_table_len = section_index + 1;
    coff_header.number_of_sections = std.mem.nativeTo(
        @TypeOf(coff_header.number_of_sections),
        section_table_len,
        target_endian,
    );
    try Node.known.section_table.resize(
        &coff.mf,
        gpa,
        @sizeOf(std.coff.SectionHeader) * section_table_len,
    );
    const ni = try coff.mf.addLastChildNode(gpa, .root, .{
        .alignment = coff.mf.flags.block_size,
        .moved = true,
    });
    const si = coff.addSymbolAssumeCapacity();
    coff.nodes.appendAssumeCapacity(.{ .section = si });
    const sym = si.get(coff);
    sym.ni = ni;
    sym.section_number = @enumFromInt(section_table_len);
    sym.data_directory = data_directory;
    const section_ptr = &coff.sectionTableSlice()[section_index];
    section_ptr.* = .{
        .name = undefined,
        .virtual_size = 0,
        .virtual_address = 0,
        .size_of_raw_data = 0,
        .pointer_to_raw_data = 0,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 0,
        .number_of_linenumbers = 0,
        .flags = flags,
    };
    @memcpy(section_ptr.name[0..name.len], name);
    @memset(section_ptr.name[name.len..], 0);
    if (target_endian != native_endian) std.mem.byteSwapAllFields(std.coff.SectionHeader, section_ptr);
    return si;
}

pub fn addReloc(
    coff: *Coff,
    loc_si: Symbol.Index,
    offset: u64,
    target_si: Symbol.Index,
    addend: i64,
    @"type": Reloc.Type,
) !void {
    const gpa = coff.base.comp.gpa;
    const target = target_si.get(coff);
    const ri: link.File.Coff2.Reloc.Index = @enumFromInt(coff.relocs.items.len);
    (try coff.relocs.addOne(gpa)).* = .{
        .type = @"type",
        .prev = .none,
        .next = target.target_relocs,
        .loc = loc_si,
        .target = target_si,
        .unused = 0,
        .offset = offset,
        .addend = addend,
    };
    switch (target.target_relocs) {
        .none => {},
        else => |target_ri| target_ri.get(coff).prev = ri,
    }
    target.target_relocs = ri;
}

pub fn prelink(coff: *Coff, prog_node: std.Progress.Node) void {
    _ = coff;
    _ = prog_node;
}

pub fn updateNav(coff: *Coff, pt: Zcu.PerThread, nav_index: InternPool.Nav.Index) !void {
    coff.updateNavInner(pt, nav_index) catch |err| switch (err) {
        error.OutOfMemory,
        error.Overflow,
        error.RelocationNotByteAligned,
        => |e| return e,
        else => |e| return coff.base.cgFail(nav_index, "linker failed to update variable: {t}", .{e}),
    };
}
fn updateNavInner(coff: *Coff, pt: Zcu.PerThread, nav_index: InternPool.Nav.Index) !void {
    const zcu = pt.zcu;
    const gpa = zcu.gpa;
    const ip = &zcu.intern_pool;

    const nav = ip.getNav(nav_index);
    const nav_val = nav.status.fully_resolved.val;
    const nav_init, const is_threadlocal = switch (ip.indexToKey(nav_val)) {
        else => .{ nav_val, false },
        .variable => |variable| .{ variable.init, variable.is_threadlocal },
        .@"extern" => return,
        .func => .{ .none, false },
    };
    if (nav_init == .none or !Type.fromInterned(ip.typeOf(nav_init)).hasRuntimeBits(zcu)) return;

    const nmi = try coff.navMapIndex(zcu, nav_index);
    const si = nmi.symbolIndex(coff);
    const ni = ni: {
        const sym = si.get(coff);
        switch (sym.ni) {
            .none => {
                try coff.nodes.ensureUnusedCapacity(gpa, 1);
                _ = is_threadlocal;
                const ni = try coff.mf.addLastChildNode(gpa, Symbol.Index.data.node(coff), .{
                    .alignment = pt.navAlignment(nav_index).toStdMem(),
                    .moved = true,
                });
                coff.nodes.appendAssumeCapacity(.{ .nav = nmi });
                sym.ni = ni;
                sym.section_number = Symbol.Index.data.get(coff).section_number;
            },
            else => si.deleteLocationRelocs(coff),
        }
        assert(sym.loc_relocs == .none);
        sym.loc_relocs = @enumFromInt(coff.relocs.items.len);
        break :ni sym.ni;
    };

    var nw: MappedFile.Node.Writer = undefined;
    ni.writer(&coff.mf, gpa, &nw);
    defer nw.deinit();
    codegen.generateSymbol(
        &coff.base,
        pt,
        zcu.navSrcLoc(nav_index),
        .fromInterned(nav_init),
        &nw.interface,
        .{ .atom_index = @intFromEnum(si) },
    ) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        else => |e| return e,
    };
    si.get(coff).size = @intCast(nw.interface.end);
    si.applyLocationRelocs(coff);
}

pub fn lowerUav(
    coff: *Coff,
    pt: Zcu.PerThread,
    uav_val: InternPool.Index,
    uav_align: InternPool.Alignment,
    src_loc: Zcu.LazySrcLoc,
) !codegen.SymbolResult {
    const zcu = pt.zcu;
    const gpa = zcu.gpa;

    try coff.pending_uavs.ensureUnusedCapacity(gpa, 1);
    const umi = try coff.uavMapIndex(uav_val);
    const si = umi.symbolIndex(coff);
    if (switch (si.get(coff).ni) {
        .none => true,
        else => |ni| uav_align.toStdMem().order(ni.alignment(&coff.mf)).compare(.gt),
    }) {
        const gop = coff.pending_uavs.getOrPutAssumeCapacity(umi);
        if (gop.found_existing) {
            gop.value_ptr.alignment = gop.value_ptr.alignment.max(uav_align);
        } else {
            gop.value_ptr.* = .{
                .alignment = uav_align,
                .src_loc = src_loc,
            };
            coff.base.comp.link_const_prog_node.increaseEstimatedTotalItems(1);
        }
    }
    return .{ .sym_index = @intFromEnum(si) };
}

pub fn updateFunc(
    coff: *Coff,
    pt: Zcu.PerThread,
    func_index: InternPool.Index,
    mir: *const codegen.AnyMir,
) !void {
    coff.updateFuncInner(pt, func_index, mir) catch |err| switch (err) {
        error.OutOfMemory,
        error.Overflow,
        error.RelocationNotByteAligned,
        error.CodegenFail,
        => |e| return e,
        else => |e| return coff.base.cgFail(
            pt.zcu.funcInfo(func_index).owner_nav,
            "linker failed to update function: {s}",
            .{@errorName(e)},
        ),
    };
}
fn updateFuncInner(
    coff: *Coff,
    pt: Zcu.PerThread,
    func_index: InternPool.Index,
    mir: *const codegen.AnyMir,
) !void {
    const zcu = pt.zcu;
    const gpa = zcu.gpa;
    const ip = &zcu.intern_pool;
    const func = zcu.funcInfo(func_index);
    const nav = ip.getNav(func.owner_nav);

    const nmi = try coff.navMapIndex(zcu, func.owner_nav);
    const si = nmi.symbolIndex(coff);
    log.debug("updateFunc({f}) = {d}", .{ nav.fqn.fmt(ip), si });
    const ni = ni: {
        const sym = si.get(coff);
        switch (sym.ni) {
            .none => {
                try coff.nodes.ensureUnusedCapacity(gpa, 1);
                const mod = zcu.navFileScope(func.owner_nav).mod.?;
                const target = &mod.resolved_target.result;
                const ni = try coff.mf.addLastChildNode(gpa, Symbol.Index.text.node(coff), .{
                    .alignment = switch (nav.status.fully_resolved.alignment) {
                        .none => switch (mod.optimize_mode) {
                            .Debug,
                            .ReleaseSafe,
                            .ReleaseFast,
                            => target_util.defaultFunctionAlignment(target),
                            .ReleaseSmall => target_util.minFunctionAlignment(target),
                        },
                        else => |a| a.maxStrict(target_util.minFunctionAlignment(target)),
                    }.toStdMem(),
                    .moved = true,
                });
                coff.nodes.appendAssumeCapacity(.{ .nav = nmi });
                sym.ni = ni;
                sym.section_number = Symbol.Index.text.get(coff).section_number;
            },
            else => si.deleteLocationRelocs(coff),
        }
        assert(sym.loc_relocs == .none);
        sym.loc_relocs = @enumFromInt(coff.relocs.items.len);
        break :ni sym.ni;
    };

    var nw: MappedFile.Node.Writer = undefined;
    ni.writer(&coff.mf, gpa, &nw);
    defer nw.deinit();
    codegen.emitFunction(
        &coff.base,
        pt,
        zcu.navSrcLoc(func.owner_nav),
        func_index,
        @intFromEnum(si),
        mir,
        &nw.interface,
        .none,
    ) catch |err| switch (err) {
        error.WriteFailed => return nw.err.?,
        else => |e| return e,
    };
    si.get(coff).size = @intCast(nw.interface.end);
    si.applyLocationRelocs(coff);
}

pub fn updateErrorData(coff: *Coff, pt: Zcu.PerThread) !void {
    coff.flushLazy(pt, .{
        .kind = .const_data,
        .index = @intCast(coff.lazy.getPtr(.const_data).map.getIndex(.anyerror_type) orelse return),
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.CodegenFail => return error.LinkFailure,
        else => |e| return coff.base.comp.link_diags.fail("updateErrorData failed {t}", .{e}),
    };
}

pub fn flush(
    coff: *Coff,
    arena: std.mem.Allocator,
    tid: Zcu.PerThread.Id,
    prog_node: std.Progress.Node,
) !void {
    _ = arena;
    _ = prog_node;
    while (try coff.idle(tid)) {}

    // hack for stage2_x86_64 + coff
    const comp = coff.base.comp;
    if (comp.compiler_rt_dyn_lib) |crt_file| {
        const gpa = comp.gpa;
        const compiler_rt_sub_path = try std.fs.path.join(gpa, &.{
            std.fs.path.dirname(coff.base.emit.sub_path) orelse "",
            std.fs.path.basename(crt_file.full_object_path.sub_path),
        });
        defer gpa.free(compiler_rt_sub_path);
        crt_file.full_object_path.root_dir.handle.copyFile(
            crt_file.full_object_path.sub_path,
            coff.base.emit.root_dir.handle,
            compiler_rt_sub_path,
            .{},
        ) catch |err| switch (err) {
            else => |e| return comp.link_diags.fail("Copy '{s}' failed: {s}", .{
                compiler_rt_sub_path,
                @errorName(e),
            }),
        };
    }
}

pub fn idle(coff: *Coff, tid: Zcu.PerThread.Id) !bool {
    const comp = coff.base.comp;
    task: {
        while (coff.pending_uavs.pop()) |pending_uav| {
            const sub_prog_node = coff.idleProgNode(
                tid,
                comp.link_const_prog_node,
                .{ .uav = pending_uav.key },
            );
            defer sub_prog_node.end();
            coff.flushUav(
                .{ .zcu = coff.base.comp.zcu.?, .tid = tid },
                pending_uav.key,
                pending_uav.value.alignment,
                pending_uav.value.src_loc,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |e| return coff.base.comp.link_diags.fail(
                    "linker failed to lower constant: {t}",
                    .{e},
                ),
            };
            break :task;
        }
        if (coff.global_pending_index < coff.globals.count()) {
            const pt: Zcu.PerThread = .{ .zcu = coff.base.comp.zcu.?, .tid = tid };
            const gmi: Node.GlobalMapIndex = @enumFromInt(coff.global_pending_index);
            coff.global_pending_index += 1;
            const sub_prog_node = comp.link_synth_prog_node.start(
                gmi.globalName(coff).name.toSlice(coff),
                0,
            );
            defer sub_prog_node.end();
            coff.flushGlobal(pt, gmi) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |e| return coff.base.comp.link_diags.fail(
                    "linker failed to lower constant: {t}",
                    .{e},
                ),
            };
            break :task;
        }
        var lazy_it = coff.lazy.iterator();
        while (lazy_it.next()) |lazy| if (lazy.value.pending_index < lazy.value.map.count()) {
            const pt: Zcu.PerThread = .{ .zcu = coff.base.comp.zcu.?, .tid = tid };
            const lmr: Node.LazyMapRef = .{ .kind = lazy.key, .index = lazy.value.pending_index };
            lazy.value.pending_index += 1;
            const kind = switch (lmr.kind) {
                .code => "code",
                .const_data => "data",
            };
            var name: [std.Progress.Node.max_name_len]u8 = undefined;
            const sub_prog_node = comp.link_synth_prog_node.start(
                std.fmt.bufPrint(&name, "lazy {s} for {f}", .{
                    kind,
                    Type.fromInterned(lmr.lazySymbol(coff).ty).fmt(pt),
                }) catch &name,
                0,
            );
            defer sub_prog_node.end();
            coff.flushLazy(pt, lmr) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |e| return coff.base.comp.link_diags.fail(
                    "linker failed to lower lazy {s}: {t}",
                    .{ kind, e },
                ),
            };
            break :task;
        };
        while (coff.mf.updates.pop()) |ni| {
            const clean_moved = ni.cleanMoved(&coff.mf);
            const clean_resized = ni.cleanResized(&coff.mf);
            if (clean_moved or clean_resized) {
                const sub_prog_node = coff.idleProgNode(tid, coff.mf.update_prog_node, coff.getNode(ni));
                defer sub_prog_node.end();
                if (clean_moved) try coff.flushMoved(ni);
                if (clean_resized) try coff.flushResized(ni);
                break :task;
            } else coff.mf.update_prog_node.completeOne();
        }
    }
    if (coff.pending_uavs.count() > 0) return true;
    for (&coff.lazy.values) |lazy| if (lazy.map.count() > lazy.pending_index) return true;
    if (coff.mf.updates.items.len > 0) return true;
    return false;
}

fn idleProgNode(
    coff: *Coff,
    tid: Zcu.PerThread.Id,
    prog_node: std.Progress.Node,
    node: Node,
) std.Progress.Node {
    var name: [std.Progress.Node.max_name_len]u8 = undefined;
    return prog_node.start(name: switch (node) {
        else => |tag| @tagName(tag),
        .section => |si| std.mem.sliceTo(&si.get(coff).section_number.get(coff).name, 0),
        .nav => |nmi| {
            const ip = &coff.base.comp.zcu.?.intern_pool;
            break :name ip.getNav(nmi.navIndex(coff)).fqn.toSlice(ip);
        },
        .uav => |umi| std.fmt.bufPrint(&name, "{f}", .{
            Value.fromInterned(umi.uavValue(coff)).fmtValue(.{
                .zcu = coff.base.comp.zcu.?,
                .tid = tid,
            }),
        }) catch &name,
    }, 0);
}

fn flushUav(
    coff: *Coff,
    pt: Zcu.PerThread,
    umi: Node.UavMapIndex,
    uav_align: InternPool.Alignment,
    src_loc: Zcu.LazySrcLoc,
) !void {
    const zcu = pt.zcu;
    const gpa = zcu.gpa;

    const uav_val = umi.uavValue(coff);
    const si = umi.symbolIndex(coff);
    const ni = ni: {
        const sym = si.get(coff);
        switch (sym.ni) {
            .none => {
                try coff.nodes.ensureUnusedCapacity(gpa, 1);
                const ni = try coff.mf.addLastChildNode(gpa, Symbol.Index.data.node(coff), .{
                    .alignment = uav_align.toStdMem(),
                    .moved = true,
                });
                coff.nodes.appendAssumeCapacity(.{ .uav = umi });
                sym.ni = ni;
                sym.section_number = Symbol.Index.data.get(coff).section_number;
            },
            else => {
                if (sym.ni.alignment(&coff.mf).order(uav_align.toStdMem()).compare(.gte)) return;
                si.deleteLocationRelocs(coff);
            },
        }
        assert(sym.loc_relocs == .none);
        sym.loc_relocs = @enumFromInt(coff.relocs.items.len);
        break :ni sym.ni;
    };

    var nw: MappedFile.Node.Writer = undefined;
    ni.writer(&coff.mf, gpa, &nw);
    defer nw.deinit();
    codegen.generateSymbol(
        &coff.base,
        pt,
        src_loc,
        .fromInterned(uav_val),
        &nw.interface,
        .{ .atom_index = @intFromEnum(si) },
    ) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        else => |e| return e,
    };
    si.get(coff).size = @intCast(nw.interface.end);
    si.applyLocationRelocs(coff);
}

fn flushGlobal(coff: *Coff, pt: Zcu.PerThread, gmi: Node.GlobalMapIndex) !void {
    const zcu = pt.zcu;
    const comp = zcu.comp;
    const gpa = zcu.gpa;
    const gn = gmi.globalName(coff);
    if (gn.lib_name.toSlice(coff)) |lib_name| {
        const name = gn.name.toSlice(coff);
        try coff.nodes.ensureUnusedCapacity(gpa, 4);
        try coff.symtab.ensureUnusedCapacity(gpa, 1);

        const target_endian = coff.endian();
        const magic = coff.optionalHeaderMagic();
        const addr_size: u64, const addr_align: std.mem.Alignment = switch (magic) {
            _ => unreachable,
            .PE32 => .{ 4, .@"4" },
            .@"PE32+" => .{ 8, .@"8" },
        };

        const gop = try coff.import_table.dlls.getOrPutAdapted(
            gpa,
            lib_name,
            ImportTable.Adapter{ .coff = coff },
        );
        const import_hint_name_align: std.mem.Alignment = .@"2";
        if (!gop.found_existing) {
            errdefer _ = coff.import_table.dlls.pop();
            try coff.import_table.directory_table_ni.resize(
                &coff.mf,
                gpa,
                @sizeOf(std.coff.ImportDirectoryEntry) * (gop.index + 2),
            );
            const import_directory_table: []std.coff.ImportDirectoryEntry =
                @ptrCast(@alignCast(coff.import_table.directory_table_ni.slice(&coff.mf)));
            const import_directory_entries = import_directory_table[gop.index..][0..2];
            @memset(import_directory_entries, .{
                .import_lookup_table_rva = 0,
                .time_date_stamp = 0,
                .forwarder_chain = 0,
                .name_rva = 0,
                .import_address_table_rva = 0,
            });
            const import_hint_name_table_len =
                import_hint_name_align.forward(lib_name.len + ".dll".len + 1);
            const idata_section_ni = Symbol.Index.idata.node(coff);
            const import_lookup_table_ni = try coff.mf.addLastChildNode(gpa, idata_section_ni, .{
                .alignment = addr_align,
                .moved = true,
            });
            const import_address_table_si = coff.addSymbolAssumeCapacity();
            const import_address_table_sym = import_address_table_si.get(coff);
            import_address_table_sym.ni = try coff.mf.addLastChildNode(gpa, idata_section_ni, .{
                .alignment = addr_align,
                .moved = true,
            });
            import_address_table_sym.section_number = Symbol.Index.idata.get(coff).section_number;
            assert(import_address_table_sym.loc_relocs == .none);
            import_address_table_sym.loc_relocs = @enumFromInt(coff.relocs.items.len);
            const import_hint_name_table_ni = try coff.mf.addLastChildNode(gpa, idata_section_ni, .{
                .size = import_hint_name_table_len,
                .alignment = import_hint_name_align,
                .moved = true,
            });
            gop.value_ptr.* = .{
                .import_lookup_table_ni = import_lookup_table_ni,
                .import_address_table_si = import_address_table_si,
                .import_hint_name_table_ni = import_hint_name_table_ni,
                .len = 0,
                .hint_name_len = @intCast(import_hint_name_table_len),
            };
            const import_hint_name_slice = import_hint_name_table_ni.slice(&coff.mf);
            @memcpy(import_hint_name_slice[0..lib_name.len], lib_name);
            @memcpy(import_hint_name_slice[lib_name.len..][0..".dll".len], ".dll");
            @memset(import_hint_name_slice[lib_name.len + ".dll".len ..], 0);
            coff.nodes.appendAssumeCapacity(.{ .import_lookup_table = @intCast(gop.index) });
            coff.nodes.appendAssumeCapacity(.{ .import_address_table = @intCast(gop.index) });
            coff.nodes.appendAssumeCapacity(.{ .import_hint_name_table = @intCast(gop.index) });
        }
        const import_symbol_index = gop.value_ptr.len;
        gop.value_ptr.len = import_symbol_index + 1;
        const new_symbol_table_size = addr_size * (import_symbol_index + 2);
        const import_hint_name_index = gop.value_ptr.hint_name_len;
        gop.value_ptr.hint_name_len = @intCast(
            import_hint_name_align.forward(import_hint_name_index + 2 + name.len + 1),
        );
        try gop.value_ptr.import_lookup_table_ni.resize(&coff.mf, gpa, new_symbol_table_size);
        const import_address_table_ni = gop.value_ptr.import_address_table_si.node(coff);
        try import_address_table_ni.resize(&coff.mf, gpa, new_symbol_table_size);
        try gop.value_ptr.import_hint_name_table_ni.resize(
            &coff.mf,
            gpa,
            gop.value_ptr.hint_name_len,
        );
        const import_lookup_slice = gop.value_ptr.import_lookup_table_ni.slice(&coff.mf);
        const import_address_slice = import_address_table_ni.slice(&coff.mf);
        const import_hint_name_slice = gop.value_ptr.import_hint_name_table_ni.slice(&coff.mf);
        @memset(import_hint_name_slice[import_hint_name_index..][0..2], 0);
        @memcpy(
            import_hint_name_slice[import_hint_name_index + 2 ..][0..name.len],
            name,
        );
        @memset(import_hint_name_slice[import_hint_name_index + 2 + name.len ..], 0);
        const import_hint_name_file_offset =
            gop.value_ptr.import_hint_name_table_ni.fileLocation(&coff.mf, false).offset +
            import_hint_name_index;
        switch (magic) {
            _ => unreachable,
            inline .PE32, .@"PE32+" => |ct_magic| {
                const Addr = switch (ct_magic) {
                    _ => comptime unreachable,
                    .PE32 => u32,
                    .@"PE32+" => u64,
                };
                const import_lookup_table: []Addr = @ptrCast(@alignCast(import_lookup_slice));
                const import_address_table: []Addr = @ptrCast(@alignCast(import_address_slice));
                const import_hint_name_rvas: [2]Addr = .{
                    std.mem.nativeTo(Addr, @intCast(import_hint_name_file_offset), target_endian),
                    std.mem.nativeTo(Addr, 0, target_endian),
                };
                import_lookup_table[import_symbol_index..][0..2].* = import_hint_name_rvas;
                import_address_table[import_symbol_index..][0..2].* = import_hint_name_rvas;
            },
        }
        const si = gmi.symbolIndex(coff);
        const sym = si.get(coff);
        sym.section_number = Symbol.Index.text.get(coff).section_number;
        assert(sym.loc_relocs == .none);
        sym.loc_relocs = @enumFromInt(coff.relocs.items.len);
        switch (coff.headerField(.machine)) {
            else => |tag| @panic(@tagName(tag)),
            .AMD64 => {
                const init = [_]u8{ 0xff, 0x25, 0x00, 0x00, 0x00, 0x00 };
                const target = &comp.root_mod.resolved_target.result;
                const ni = try coff.mf.addLastChildNode(gpa, Symbol.Index.text.node(coff), .{
                    .alignment = switch (comp.root_mod.optimize_mode) {
                        .Debug,
                        .ReleaseSafe,
                        .ReleaseFast,
                        => target_util.defaultFunctionAlignment(target),
                        .ReleaseSmall => target_util.minFunctionAlignment(target),
                    }.toStdMem(),
                    .size = init.len,
                    .moved = true,
                });
                @memcpy(ni.slice(&coff.mf)[0..init.len], &init);
                sym.ni = ni;
                sym.size = init.len;
                try coff.addReloc(
                    si,
                    init.len - 4,
                    gop.value_ptr.import_address_table_si,
                    @intCast(addr_size * import_symbol_index),
                    .{ .AMD64 = .REL32 },
                );
            },
        }
        coff.nodes.appendAssumeCapacity(.{ .global = gmi });
        si.applyLocationRelocs(coff);
    }
}

fn flushLazy(coff: *Coff, pt: Zcu.PerThread, lmr: Node.LazyMapRef) !void {
    const zcu = pt.zcu;
    const gpa = zcu.gpa;

    const lazy = lmr.lazySymbol(coff);
    const si = lmr.symbolIndex(coff);
    const ni = ni: {
        const sym = si.get(coff);
        switch (sym.ni) {
            .none => {
                try coff.nodes.ensureUnusedCapacity(gpa, 1);
                const sec_si: Symbol.Index = switch (lazy.kind) {
                    .code => .text,
                    .const_data => .rdata,
                };
                const ni = try coff.mf.addLastChildNode(gpa, sec_si.node(coff), .{ .moved = true });
                coff.nodes.appendAssumeCapacity(switch (lazy.kind) {
                    .code => .{ .lazy_code = @enumFromInt(lmr.index) },
                    .const_data => .{ .lazy_const_data = @enumFromInt(lmr.index) },
                });
                sym.ni = ni;
                sym.section_number = sec_si.get(coff).section_number;
            },
            else => si.deleteLocationRelocs(coff),
        }
        assert(sym.loc_relocs == .none);
        sym.loc_relocs = @enumFromInt(coff.relocs.items.len);
        break :ni sym.ni;
    };

    var required_alignment: InternPool.Alignment = .none;
    var nw: MappedFile.Node.Writer = undefined;
    ni.writer(&coff.mf, gpa, &nw);
    defer nw.deinit();
    try codegen.generateLazySymbol(
        &coff.base,
        pt,
        Type.fromInterned(lazy.ty).srcLocOrNull(pt.zcu) orelse .unneeded,
        lazy,
        &required_alignment,
        &nw.interface,
        .none,
        .{ .atom_index = @intFromEnum(si) },
    );
    si.get(coff).size = @intCast(nw.interface.end);
    si.applyLocationRelocs(coff);
}

fn flushMoved(coff: *Coff, ni: MappedFile.Node.Index) !void {
    const target_endian = coff.endian();
    const file_offset = ni.fileLocation(&coff.mf, false).offset;
    const node = coff.getNode(ni);
    switch (node) {
        else => |tag| @panic(@tagName(tag)),
        .header, .signature => assert(file_offset == 0),
        .coff_header,
        .optional_header,
        .data_directories,
        .section_table,
        => {},
        .section => |si| {
            const sym = si.get(coff);
            const sec = sym.section_number.get(coff);
            sec.virtual_address =
                std.mem.nativeTo(@TypeOf(sec.virtual_address), @intCast(file_offset), target_endian);
            sec.pointer_to_raw_data = std.mem.nativeTo(
                @TypeOf(sec.pointer_to_raw_data),
                @intCast(file_offset),
                target_endian,
            );
            if (sym.data_directory) |data_directory|
                coff.dataDirectoriesSlice()[@intFromEnum(data_directory)].virtual_address =
                    sec.virtual_address;
        },
        .import_directory_table => {},
        .import_lookup_table => |import_directory_table_index| {
            const import_directory_table: []std.coff.ImportDirectoryEntry =
                @ptrCast(@alignCast(coff.import_table.directory_table_ni.slice(&coff.mf)));
            const import_directory_entry = &import_directory_table[import_directory_table_index];
            import_directory_entry.import_lookup_table_rva = std.mem.nativeTo(
                @TypeOf(import_directory_entry.import_lookup_table_rva),
                @intCast(file_offset),
                target_endian,
            );
        },
        .import_address_table => |import_directory_table_index| {
            const import_directory_table: []std.coff.ImportDirectoryEntry =
                @ptrCast(@alignCast(coff.import_table.directory_table_ni.slice(&coff.mf)));
            const import_directory_entry = &import_directory_table[import_directory_table_index];
            import_directory_entry.import_address_table_rva = std.mem.nativeTo(
                @TypeOf(import_directory_entry.import_address_table_rva),
                @intCast(file_offset),
                target_endian,
            );
            coff.import_table.dlls.values()[import_directory_table_index]
                .import_address_table_si.flushMoved(coff, file_offset);
        },
        .import_hint_name_table => |import_directory_table_index| {
            const magic = coff.optionalHeaderMagic();
            const import_directory_table: []std.coff.ImportDirectoryEntry =
                @ptrCast(@alignCast(coff.import_table.directory_table_ni.slice(&coff.mf)));
            const import_directory_entry = &import_directory_table[import_directory_table_index];
            import_directory_entry.name_rva = std.mem.nativeTo(
                @TypeOf(import_directory_entry.name_rva),
                @intCast(file_offset),
                target_endian,
            );
            const import_entry = &coff.import_table.dlls.values()[import_directory_table_index];
            const import_lookup_slice = import_entry.import_lookup_table_ni.slice(&coff.mf);
            const import_address_slice =
                import_entry.import_address_table_si.node(coff).slice(&coff.mf);
            const import_hint_name_slice = ni.slice(&coff.mf);
            const import_hint_name_align = ni.alignment(&coff.mf);
            var import_hint_name_index: usize = 0;
            for (0..import_entry.len) |import_symbol_index| {
                import_hint_name_index = import_hint_name_align.forward(std.mem.indexOfScalarPos(
                    u8,
                    import_hint_name_slice,
                    import_hint_name_index,
                    0,
                ).? + 1);
                switch (magic) {
                    _ => unreachable,
                    inline .PE32, .@"PE32+" => |ct_magic| {
                        const Addr = switch (ct_magic) {
                            _ => comptime unreachable,
                            .PE32 => u32,
                            .@"PE32+" => u64,
                        };
                        const import_lookup_table: []Addr = @ptrCast(@alignCast(import_lookup_slice));
                        const import_address_table: []Addr = @ptrCast(@alignCast(import_address_slice));
                        const rva = std.mem.nativeTo(
                            Addr,
                            @intCast(file_offset + import_hint_name_index),
                            native_endian,
                        );
                        import_lookup_table[import_symbol_index] = rva;
                        import_address_table[import_symbol_index] = rva;
                    },
                }
                import_hint_name_index += 2;
            }
        },
        inline .global,
        .nav,
        .uav,
        .lazy_code,
        .lazy_const_data,
        => |mi| mi.symbolIndex(coff).flushMoved(coff, file_offset),
    }
    try ni.childrenMoved(coff.base.comp.gpa, &coff.mf);
}

fn flushResized(coff: *Coff, ni: MappedFile.Node.Index) !void {
    const target_endian = coff.endian();
    _, const size = ni.location(&coff.mf).resolve(&coff.mf);
    const node = coff.getNode(ni);
    switch (node) {
        else => |tag| @panic(@tagName(tag)),
        .file => switch (coff.optionalHeaderPtr()) {
            inline else => |header| header.size_of_image =
                std.mem.nativeTo(@TypeOf(header.size_of_image), @intCast(size), target_endian),
        },
        .header => switch (coff.optionalHeaderPtr()) {
            inline else => |header| header.size_of_headers =
                std.mem.nativeTo(@TypeOf(header.size_of_headers), @intCast(size), target_endian),
        },
        .section_table => {},
        .section => |si| {
            const sym = si.get(coff);
            const sec = sym.section_number.get(coff);
            sec.virtual_size = std.mem.nativeTo(
                @TypeOf(sec.virtual_size),
                @intCast(size),
                target_endian,
            );
            sec.size_of_raw_data = sec.virtual_size;
            if (sym.data_directory) |data_directory|
                coff.dataDirectoriesSlice()[@intFromEnum(data_directory)].size = sec.virtual_size;
        },
        .import_directory_table,
        .import_lookup_table,
        .import_address_table,
        .import_hint_name_table,
        .global,
        .nav,
        .uav,
        .lazy_code,
        .lazy_const_data,
        => {},
    }
}

pub fn updateExports(
    coff: *Coff,
    pt: Zcu.PerThread,
    exported: Zcu.Exported,
    export_indices: []const Zcu.Export.Index,
) !void {
    return coff.updateExportsInner(pt, exported, export_indices) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.LinkFailure => error.AnalysisFail,
    };
}
fn updateExportsInner(
    coff: *Coff,
    pt: Zcu.PerThread,
    exported: Zcu.Exported,
    export_indices: []const Zcu.Export.Index,
) !void {
    const zcu = pt.zcu;
    const gpa = zcu.gpa;
    const ip = &zcu.intern_pool;

    switch (exported) {
        .nav => |nav| log.debug("updateExports({f})", .{ip.getNav(nav).fqn.fmt(ip)}),
        .uav => |uav| log.debug("updateExports(@as({f}, {f}))", .{
            Type.fromInterned(ip.typeOf(uav)).fmt(pt),
            Value.fromInterned(uav).fmtValue(pt),
        }),
    }
    try coff.symtab.ensureUnusedCapacity(gpa, export_indices.len);
    const exported_si: Symbol.Index = switch (exported) {
        .nav => |nav| try coff.navSymbol(zcu, nav),
        .uav => |uav| @enumFromInt(switch (try coff.lowerUav(
            pt,
            uav,
            Type.fromInterned(ip.typeOf(uav)).abiAlignment(zcu),
            export_indices[0].ptr(zcu).src,
        )) {
            .sym_index => |si| si,
            .fail => |em| {
                defer em.destroy(gpa);
                return coff.base.comp.link_diags.fail("{s}", .{em.msg});
            },
        }),
    };
    while (try coff.idle(pt.tid)) {}
    const exported_ni = exported_si.node(coff);
    const exported_sym = exported_si.get(coff);
    for (export_indices) |export_index| {
        const @"export" = export_index.ptr(zcu);
        const export_si = try coff.globalSymbol(@"export".opts.name.toSlice(ip), null);
        const export_sym = export_si.get(coff);
        export_sym.ni = exported_ni;
        export_sym.rva = exported_sym.rva;
        export_sym.size = exported_sym.size;
        export_sym.section_number = exported_sym.section_number;
        export_si.applyTargetRelocs(coff);
        if (@"export".opts.name.eqlSlice("wWinMainCRTStartup", ip)) {
            coff.entry_hack = exported_si;
            switch (coff.optionalHeaderPtr()) {
                inline else => |header| header.address_of_entry_point = exported_sym.rva,
            }
        }
    }
}

pub fn deleteExport(coff: *Coff, exported: Zcu.Exported, name: InternPool.NullTerminatedString) void {
    _ = coff;
    _ = exported;
    _ = name;
}

pub fn dump(coff: *Coff, tid: Zcu.PerThread.Id) void {
    const w = std.debug.lockStderrWriter(&.{});
    defer std.debug.unlockStderrWriter();
    coff.printNode(tid, w, .root, 0) catch {};
}

pub fn printNode(
    coff: *Coff,
    tid: Zcu.PerThread.Id,
    w: *std.Io.Writer,
    ni: MappedFile.Node.Index,
    indent: usize,
) !void {
    const node = coff.getNode(ni);
    const mf_node = &coff.mf.nodes.items[@intFromEnum(ni)];
    const off, const size = mf_node.location().resolve(&coff.mf);
    try w.splatByteAll(' ', indent);
    try w.writeAll(@tagName(node));
    switch (node) {
        else => {},
        .section => |si| try w.print("({s})", .{
            std.mem.sliceTo(&si.get(coff).section_number.get(coff).name, 0),
        }),
        .import_lookup_table,
        .import_address_table,
        .import_hint_name_table,
        => |import_directory_table_index| try w.print("({s})", .{
            std.mem.sliceTo(coff.import_table.dlls.values()[import_directory_table_index]
                .import_hint_name_table_ni.sliceConst(&coff.mf), 0),
        }),
        .global => |gmi| {
            const gn = gmi.globalName(coff);
            try w.writeByte('(');
            if (gn.lib_name.toSlice(coff)) |lib_name| try w.print("{s}.dll, ", .{lib_name});
            try w.print("{s})", .{gn.name.toSlice(coff)});
        },
        .nav => |nmi| {
            const zcu = coff.base.comp.zcu.?;
            const ip = &zcu.intern_pool;
            const nav = ip.getNav(nmi.navIndex(coff));
            try w.print("({f}, {f})", .{
                Type.fromInterned(nav.typeOf(ip)).fmt(.{ .zcu = zcu, .tid = tid }),
                nav.fqn.fmt(ip),
            });
        },
        .uav => |umi| {
            const zcu = coff.base.comp.zcu.?;
            const val: Value = .fromInterned(umi.uavValue(coff));
            try w.print("({f}, {f})", .{
                val.typeOf(zcu).fmt(.{ .zcu = zcu, .tid = tid }),
                val.fmtValue(.{ .zcu = zcu, .tid = tid }),
            });
        },
        inline .lazy_code, .lazy_const_data => |lmi| try w.print("({f})", .{
            Type.fromInterned(lmi.lazySymbol(coff).ty).fmt(.{
                .zcu = coff.base.comp.zcu.?,
                .tid = tid,
            }),
        }),
    }
    try w.print(" index={d} offset=0x{x} size=0x{x} align=0x{x}{s}{s}{s}{s}\n", .{
        @intFromEnum(ni),
        off,
        size,
        mf_node.flags.alignment.toByteUnits(),
        if (mf_node.flags.fixed) " fixed" else "",
        if (mf_node.flags.moved) " moved" else "",
        if (mf_node.flags.resized) " resized" else "",
        if (mf_node.flags.has_content) " has_content" else "",
    });
    var child_ni = mf_node.first;
    switch (child_ni) {
        .none => {
            const file_loc = ni.fileLocation(&coff.mf, false);
            if (file_loc.size == 0) return;
            var address = file_loc.offset;
            const line_len = 0x10;
            var line_it = std.mem.window(
                u8,
                coff.mf.contents[@intCast(file_loc.offset)..][0..@intCast(file_loc.size)],
                line_len,
                line_len,
            );
            while (line_it.next()) |line_bytes| : (address += line_len) {
                try w.splatByteAll(' ', indent + 1);
                try w.print("{x:0>8}  ", .{address});
                for (line_bytes) |byte| try w.print("{x:0>2} ", .{byte});
                try w.splatByteAll(' ', 3 * (line_len - line_bytes.len) + 1);
                for (line_bytes) |byte| try w.writeByte(if (std.ascii.isPrint(byte)) byte else '.');
                try w.writeByte('\n');
            }
        },
        else => while (child_ni != .none) {
            try coff.printNode(tid, w, child_ni, indent + 1);
            child_ni = coff.mf.nodes.items[@intFromEnum(child_ni)].next;
        },
    }
}

const assert = std.debug.assert;
const builtin = @import("builtin");
const codegen = @import("../codegen.zig");
const Compilation = @import("../Compilation.zig");
const Coff = @This();
const InternPool = @import("../InternPool.zig");
const link = @import("../link.zig");
const log = std.log.scoped(.link);
const MappedFile = @import("MappedFile.zig");
const native_endian = builtin.cpu.arch.endian();
const std = @import("std");
const target_util = @import("../target.zig");
const Type = @import("../Type.zig");
const Value = @import("../Value.zig");
const Zcu = @import("../Zcu.zig");
