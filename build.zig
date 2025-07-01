const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const netlib = b.addModule("netlib", .{
        .root_source_file = b.path("src/netlib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{ .name = "netlib", .root_module = exe_mod });
    b.installArtifact(exe);

    // RUN
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // TESTS
    const test_step = b.step("test", "Run unit tests");

    const exe_tests = b.addTest(.{ .root_module = exe_mod });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    test_step.dependOn(&run_exe_tests.step);
    const netlib_tests = b.addTest(.{ .root_module = netlib });
    const run_netlib_tests = b.addRunArtifact(netlib_tests);
    test_step.dependOn(&run_netlib_tests.step);
}
