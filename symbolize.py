#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import re
import sys
import argparse
import glob
import subprocess

g_last_exception_place_holder = '$Last Exception$'
g_thread_list_place_holder = '$thread list$'
g_max_name_width = 0
g_registers = {
    'x': ['x0', 'x1', 'x2', 'x3',
          'x4', 'x5', 'x6', 'x7',
          'x8', 'x9', 'x10', 'x11',
          'x12', 'x13', 'x14', 'x15',
          'x16', 'x17', 'x18', 'x19',
          'x20', 'x21', 'x22', 'x23',
          'x24', 'x25', 'x26', 'x27',
          'x28']
}

# modules in crash report
g_name_info_map = {}
g_uuid_header_addr_map = {}
g_symbols_cache = {}


class CrashInfo:
    device_model = ''
    os_version = ''
    os_build = ''
    app_path = ''


g_crash_info = CrashInfo()


class Options:
    force_resymbolize = False
    verbose = False
    dsym = ''


g_options = Options()


def symbolize_crash_report(file_path):
    report_str = ''
    if not os.path.exists(file_path):
        print('No such file: {}'.format(file_path))
        return report_str

    if file_path.endswith('.ips'):
        report_str = symbolize_ips_file(file_path)
        if 'isn\'t json format' in report_str:
            report_str = symbolize_crash_file(file_path)
    elif file_path.endswith('.crash'):
        report_str = symbolize_crash_file(file_path)

    return report_str


def symbolize_ips_file(file_path):
    with open(file_path, 'r') as report_file:
        header_line = report_file.readline()
        if not header_line.startswith('{'):
            final_report = 'unsupported yet'
            report_file.close()

            return final_report

        # header_dict = json.loads(header_line)
        # print(json.dumps(header_dict, indent=2))

        data_str = report_file.read().replace(header_line + '\n', '')
        report_file.close()

    if data_str.startswith('{'):
        is_json = True
    else:
        is_json = False

    if is_json:
        data_dict = json.loads(data_str)

        used_images = data_dict.get('usedImages')
        max_width = 0
        for image_dict in used_images:
            image_name = image_dict.get('name')
            if not image_name:
                continue
            name_len = len(image_name)
            if name_len > max_width:
                max_width = name_len

        final_report = ''
        report_header, last_exception = build_header(data_dict)
        image_list = build_images(data_dict)

        last_exception_obj = None
        if last_exception:
            last_exception_obj = build_last_exception(last_exception, used_images, max_width)

        thread_list = build_threads(data_dict, used_images, max_width)

        symbolize_thread_list(last_exception_obj, thread_list)

        if last_exception:
            report_header = report_header.replace(g_last_exception_place_holder, last_exception_obj.description())

        final_report += report_header
        for thread in thread_list:
            final_report += ' \n{}'.format(thread.description())

        final_report += build_thread_state(data_dict)
        final_report += image_list
        final_report += build_vm_summary(data_dict)
        final_report += build_report_notes(data_dict)

        final_report += ' \nEOF\n'
    else:
        final_report = 'unsupported yet, isn\'t json format'

    return final_report


def build_header(data_dict):
    report_header = """-------------------------------------
Translated Report (Full Report Below)
-------------------------------------
"""
    report_header += '\n'
    report_header += 'Incident Identifier: {}\n'.format(data_dict.get('incident'))

    storeInfo = data_dict.get('storeInfo')
    beta_identifier = storeInfo.get('deviceIdentifierForVendor')
    if beta_identifier:
        report_header += 'Beta Identifier:     {}\n'.format(beta_identifier)

    crash_reporterKey = data_dict.get('crashReporterKey')
    if crash_reporterKey:
        report_header += 'CrashReporter Key:   {}\n'.format(crash_reporterKey)

    device_model = data_dict.get('modelCode')
    g_crash_info.device_model = device_model
    report_header += 'Hardware Model:      {}\n'.format(device_model)
    report_header += 'Process:             {} [{}]\n'.format(data_dict.get('procName'), data_dict.get('pid'))
    proc_path = data_dict.get('procPath')
    report_header += 'Path:                {}\n'.format(proc_path)
    g_crash_info.app_path = os.path.dirname(proc_path).replace('/private', '')

    bundleInfo = data_dict.get('bundleInfo')
    if bundleInfo:
        report_header += 'Identifier:          {}\n'.format(bundleInfo.get('CFBundleIdentifier'))
        report_header += 'Version:             {} ({})\n'. \
            format(bundleInfo.get('CFBundleShortVersionString'), bundleInfo.get('CFBundleVersion'))

        DTAppStoreToolsBuild = bundleInfo.get('DTAppStoreToolsBuild')
        if DTAppStoreToolsBuild:
            report_header += 'AppStoreTools:       {}\n'.format(DTAppStoreToolsBuild)

    if storeInfo:
        applicationVariant = storeInfo.get('applicationVariant')
        if applicationVariant:
            report_header += 'AppVariant:          {}\n'.format(applicationVariant)
        entitledBeta = storeInfo.get('entitledBeta')
        if entitledBeta is not None:
            report_header += 'Beta:                {}\n'.format('YES' if entitledBeta else 'NO')

    translated = data_dict.get('translated')
    code_des = 'Native'
    if translated == 'false':
        code_des = 'Translated'
    report_header += 'Code Type:           {} ({})\n'.format(data_dict.get('cpuType'), code_des)
    report_header += 'Role:                {}\n'.format(data_dict.get('procRole'))
    report_header += 'Parent Process:      {} [{}]\n'.format(data_dict.get('parentProc'), data_dict.get('parentPid'))
    report_header += 'Coalition:           {} [{}]\n'. \
        format(data_dict.get('coalitionName'), data_dict.get('coalitionID'))

    report_header += 'Date/Time:           {}\n'.format(data_dict.get('captureTime'))
    report_header += 'Launch Time:         {}\n'.format(data_dict.get('procLaunch'))

    os_version = data_dict.get('osVersion')
    if os_version:
        os_train = os_version.get('train')
        pure_os_version = match_os_version(os_train)
        g_crash_info.os_version = pure_os_version
        os_build = os_version.get('build')
        g_crash_info.os_build = os_build
        report_header += 'OS Version:          {} ({})\n'.format(os_train, os_build)
        report_header += 'Release Type:        {}\n'.format(os_version.get('releaseType'))

    basebandVersion = data_dict.get('basebandVersion')
    if basebandVersion:
        report_header += 'Baseband Version:    {}\n'.format(basebandVersion)
    report_header += 'Report Version:      {}\n'.format(data_dict.get(''))

    report_header += '\n'

    exception = data_dict.get('exception')
    if exception:
        report_header += 'Exception Type:  {} ({})\n'. \
            format(exception.get('type'), exception.get('signal'))
        subtype = exception.get('subtype')
        if subtype:
            report_header += 'Exception Subtype: {}\n'.format(subtype)
        report_header += 'Exception Codes: {}\n'.format(exception.get('codes'))

    is_corpse = data_dict.get('isCorpse')
    if is_corpse:
        report_header += 'Exception Note: EXC_CORPSE_NOTIFY'

    vm_region_info = data_dict.get('vmRegionInfo')
    if not vm_region_info:
        vm_region_info = data_dict.get('vmregioninfo')
    if vm_region_info:
        report_header += 'VM Region Info: {}\n'.format(vm_region_info)

    termination = data_dict.get('termination')
    if termination:
        indicator = termination.get('indicator')
        if indicator:
            indicator_str = ' {}'.format(indicator)
        else:
            indicator_str = ''
        report_header += 'Termination Reason: {} {} {}\n'. \
            format(termination.get('namespace'), termination.get('code'), indicator_str)

        reasons = termination.get('reasons')
        if reasons:
            report_header += '{}\n'.format(reasons)

        proc = termination.get('byProc')
        if proc:
            report_header += 'Terminating Process: {} [{}]\n'.format(proc, termination.get('byPid'))

    report_header += '\n'
    report_header += 'Triggered by Thread:  {}\n'.format(data_dict.get('faultingThread'))

    asi = data_dict.get('asi')
    if asi:
        report_header += '\n'
        report_header += 'Application Specific Information:\n'
        for key in asi:
            asi_message = '\n'.join(asi[key])
            report_header += '{}\n'.format(asi_message)

    last_exception = data_dict.get('lastExceptionBacktrace')
    if last_exception:
        report_header += ' \n{}'.format(g_last_exception_place_holder)

    kernel_triage = data_dict.get('ktriageinfo')
    if kernel_triage:
        report_header += '\n'
        report_header += 'Kernel Triage:\n{}\n'.format(kernel_triage)

    return report_header, last_exception


def build_last_exception(last_exception, used_images, max_width):
    thread_obj = Thread()
    thread_obj.title = 'Last Exception Backtrace:\n'
    thread_obj.frames = build_backtrace(last_exception, used_images, max_width)

    return thread_obj


def build_backtrace(frames, used_images, max_width):
    frame_list = []
    idx = 0
    for frame in frames:
        image_offset = frame.get('imageOffset')
        symbol = frame.get('symbol')
        imageIndex = frame.get('imageIndex')
        image_dict = used_images[imageIndex]
        image_name = image_dict.get('name')
        image_base = image_dict.get('base')
        # {'size': 0, 'source': 'A', 'base': 0, 'uuid': '00000000-0000-0000-0000-000000000000'}
        if image_base == 0:
            print('unexpected image {}'.format(image_dict))

        func_addr = image_base + image_offset

        frame_obj = Frame()
        frame_obj.idx = idx
        if image_name:
            frame_obj.image_name = image_name
        else:
            frame_obj.image_name = '???'
        frame_obj.max_width = max_width
        frame_obj.load_addr = func_addr
        frame_obj.base = image_base
        frame_obj.file_offset = image_offset
        if symbol:
            frame_obj.symbol_name = symbol
            frame_obj.symbol_offset = frame.get('symbolLocation')

        frame_list.append(frame_obj)

        idx += 1

    return frame_list


def build_threads(data_dict, used_images, max_width):
    threads = data_dict.get('threads')

    thread_list = []
    thread_idx = 0
    for thread in threads:
        thread_obj = build_thread(thread, thread_idx, used_images, max_width)
        thread_list.append(thread_obj)
        del thread_obj

        thread_idx += 1

    return thread_list


def build_thread(thread_dict, thread_idx, used_images, max_width):
    thread_title = ''
    triggered = thread_dict.get('triggered')
    queue = thread_dict.get('queue')
    thread_name = thread_dict.get('name')

    if queue:
        if not thread_name:
            thread_name = ''
        thread_title += 'Thread {} name: {} Dispatch queue: {}\n'.format(thread_idx, thread_name, queue)
    elif thread_name:
        thread_title += 'Thread {} name: {}\n'.format(thread_idx, thread_name, queue)

    trigger_flag = ''
    if triggered:
        trigger_flag = ' Crashed'
    thread_title += 'Thread {}{}:\n'.format(thread_idx, trigger_flag)

    thread_obj = Thread()
    thread_obj.title = thread_title
    frames = thread_dict.get('frames')
    thread_obj.frames = build_backtrace(frames, used_images, max_width)

    return thread_obj


def build_thread_state(data_dict):
    index = data_dict.get('faultingThread')
    threads = data_dict.get('threads')
    thread = threads[index]
    thread_state = thread.get('threadState')

    flavor = thread_state.get('flavor')
    if flavor == 'ARM_THREAD_STATE64':
        flavor_str = 'ARM Thread State (64-bit)'
    else:
        flavor_str = flavor

    thread_state_str = '\n'
    thread_state_str += 'Thread {} crashed with {}:\n  '.format(index, flavor_str)
    registers = thread_state.get('x')
    if registers:
        reg_idx = 0
        for reg in registers:
            reg_name = g_registers['x'][reg_idx]
            if reg_idx > 0 and reg_idx % 4 == 0:
                thread_state_str += '\n  {:>3}: {:#018x}  '.format(reg_name, reg.get('value'))
            else:
                thread_state_str += '{:>3}: {:#018x}  '.format(reg_name, reg.get('value'))

            reg_idx += 1

    reg_fp = thread_state.get('fp').get('value')
    reg_lr = thread_state.get('lr').get('value')
    reg_sp = thread_state.get('sp').get('value')
    reg_pc = thread_state.get('pc').get('value')
    reg_cpsr = thread_state.get('cpsr').get('value')
    reg_far = thread_state.get('far').get('value')
    esr_dict = thread_state.get('esr')
    reg_esr = esr_dict.get('value')
    esr_des = esr_dict.get('description')
    thread_state_str += ' fp: {:#018x}   lr: {:#018x}\n'.format(reg_fp, reg_lr)
    thread_state_str += '   sp: {:#018x}   pc: {:#018x} cpsr: {:#x}\n'.format(reg_sp, reg_pc, reg_cpsr)
    thread_state_str += '  far: {:#018x}  esr: {:#x} {}\n'.format(reg_far, reg_esr, esr_des)

    return thread_state_str


def build_images(data_dict):
    used_images = data_dict.get('usedImages')
    images = sorted(used_images, key=lambda image_dict: image_dict.get('base'))

    image_list = '\n'
    image_list += 'Binary Images:\n'

    global g_uuid_header_addr_map, g_name_info_map
    for image in images:
        base = image.get('base')
        size = image.get('size')
        if size > 0:
            end = base + size - 1
        else:
            end = base + size
        arch = image.get('arch')
        uuid = image.get('uuid').upper()
        path = image.get('path')
        if path:
            is_user_image = path.find(g_crash_info.app_path) != -1
        else:
            is_user_image = False
        image_name = image.get('name')

        image_list += '\t{:#x} - {:#x} {} {} <{}> {}\n'.format(base, end, image_name, arch, uuid, path)
        if '-' not in uuid:
            uuid = get_canonical_uuid_for_uuid(uuid)

        global g_uuid_header_addr_map, g_name_info_map
        g_uuid_header_addr_map[uuid] = base
        g_name_info_map[image_name] = (uuid, path, arch, is_user_image)

    image_list += 'sharedCache:\n'
    sharedCache = data_dict.get('sharedCache')
    base = sharedCache.get('base')
    size = sharedCache.get('size')
    if size > 0:
        end = base + size - 1
    else:
        end = base + size
    uuid = sharedCache.get('uuid').upper()
    image_list += '{:#x} - {:#x} <{}>\n'.format(base, end, uuid)

    return image_list


def build_vm_summary(data_dict):
    vm_des = '\n'
    vmSummary = data_dict.get('vmSummary')
    if not vmSummary:
        return ''

    vm_des += vmSummary

    return vm_des


def build_report_notes(data_dict):
    report_notes_str = '\n'
    report_notes_str += 'Error Formulating Crash Report:\n'
    report_notes = data_dict.get('reportNotes')
    if not report_notes:
        return ''
    for report_note in report_notes:
        report_notes_str += '{}\n'.format(report_note)

    return report_notes_str


def symbolize_crash_file(file_path):
    with open(file_path, 'r') as report_file:
        content = report_file.read()
        report_file.close()

    lines = content.split('\n')

    thread_list = []

    in_last_exception = False
    last_exception = None
    in_thread = False
    thread_obj = None
    thread_title = ''
    frames = None

    in_image_list = False

    final_lines = []
    for line in lines:
        line = line.strip()
        if line == 'Last Exception Backtrace:':
            if g_options.verbose:
                print('开始解析Last Exception Backtrace')
            in_last_exception = True
            last_exception = Thread()
            last_exception.title = 'Last Exception Backtrace:\n'
            frames = []
            continue
        elif line.startswith('Thread '):
            if line.find('Thread State') > 0:
                final_lines.append(g_thread_list_place_holder)
                thread_title += '{}\n'.format(line)
            elif line.endswith(':'):
                if g_options.verbose:
                    print('开始解析线程 {}'.format(line))
                in_thread = True
                thread_obj = Thread()
                thread_title += '{}\n'.format(line)
                thread_obj.title = thread_title
                thread_title = ''
                frames = []
                continue
            else:
                thread_title += '{}\n'.format(line)
                continue
        elif line.startswith('Binary Images:'):
            in_image_list = True
            continue

        if in_last_exception:
            if len(line) == 0:
                in_last_exception = False
                last_exception.frames = frames
                frames = None
                final_lines.append(g_last_exception_place_holder)
            else:
                if g_options.verbose:
                    print('解析frame {}'.format(line))
                frame_obj = parse_frame_line(line)
                frames.append(frame_obj)

            continue
        elif in_thread:
            if len(line) == 0:
                in_thread = False
                thread_obj.frames = frames
                frames = None
                thread_list.append(thread_obj)
                thread_obj = None
            else:
                if g_options.verbose:
                    print('解析frame {}'.format(line))
                frame_obj = parse_frame_line(line)
                frames.append(frame_obj)

            continue
        elif in_image_list:
            if len(line) == 0:
                in_image_list = False
            else:
                parse_image_line(line)

        if len(line) == 0:
            final_lines.append('\n')
        else:
            if 'Hardware Model:' in line:
                device_model = line.replace('Hardware Model:', '').strip()
                g_crash_info.device_model = device_model
            elif 'OS Version:' in line:
                os_version = match_os_version(line)
                os_build = match_os_build(line)
                g_crash_info.os_version = os_version
                g_crash_info.os_build = os_build
            elif line.startswith('Path:'):
                app_path = os.path.dirname(line.replace('Path:', '').strip()).replace('/private', '')
                g_crash_info.app_path = app_path

            final_lines.append(line)

    final_report = '\n'.join(final_lines)

    symbolize_thread_list(last_exception, thread_list)

    if last_exception:
        final_report = final_report.replace(g_last_exception_place_holder, last_exception.description())

    thread_list_str = ''
    for thread in thread_list:
        thread_list_str += '{} \n'.format(thread.description())

    final_report = final_report.replace(g_thread_list_place_holder, thread_list_str)

    return final_report


def replace_multiple_spaces(text):
    return re.sub(r'\s+', ' ', text)


def parse_frame_line(frame_line):
    # 4 Foundation 0x1b2ac88a8 -[NSObject(NSThreadPerformAdditions) performSelector:onThread:withObject:waitUntilDone:modes:] + 916

    frame_line = replace_multiple_spaces(frame_line)
    pos1 = frame_line.find(' ')
    frame_idx = frame_line[:pos1]
    pos2 = frame_line.find(' 0x', pos1 + 1)
    image_name = frame_line[pos1 + 1: pos2]
    pos3 = frame_line.find(' ', pos2 + 3)
    load_addr = frame_line[pos2 + 1: pos3]
    pos4 = frame_line.rfind(' + ')
    if pos4 > 0:
        name_or_addr = frame_line[pos3 + 1: pos4]
        offset = frame_line[pos4 + 3:]
    else:
        name_or_addr = frame_line[pos3 + 1:]
        offset = -1

    global g_max_name_width
    n_name = len(image_name)
    if n_name > g_max_name_width:
        g_max_name_width = n_name

    frame_obj = Frame()
    if len(frame_idx) > 0:
        frame_obj.idx = int(frame_idx)
    else:
        print('unexpected frame line: {}'.format(frame_line.encode()))

    frame_obj.image_name = image_name
    frame_obj.load_addr = int(load_addr, 16)
    if name_or_addr.startswith('0x'):
        frame_obj.base = int(name_or_addr, 16)
        frame_obj.file_offset = int(offset)
    else:
        frame_obj.symbol_name = name_or_addr
        frame_obj.symbol_offset = int(offset)
        frame_obj.file_offset = 0

    return frame_obj


def parse_image_line(image_line):
    # 0x104c9c000 - 0x104d1bfff dyld arm64 <444f50414d494e45444f50414d494e45> /usr/lib/dyld
    image_line = replace_multiple_spaces(image_line)
    pos1 = image_line.find(' - 0x')
    base = image_line[:pos1]
    pos2 = image_line.find(' ', pos1 + 4)
    pos3 = image_line.find(' ', pos2 + 1)
    image_name = image_line[pos2 + 1: pos3]
    pos4 = image_line.find('<', pos3)
    arch = image_line[pos3:pos4].strip()
    pos5 = image_line.find('>', pos4)
    uuid = image_line[pos4 + 1: pos5].upper()
    pos6 = image_line.find('/', pos5 + 1)
    path = image_line[pos6:].strip()
    is_user_image = path.find(g_crash_info.app_path) != -1

    if '-' not in uuid:
        uuid = get_canonical_uuid_for_uuid(uuid)

    global g_uuid_header_addr_map, g_name_info_map
    g_uuid_header_addr_map[uuid] = int(base, 16)
    g_name_info_map[image_name] = (uuid, path, arch, is_user_image)


def symbolize_thread_list(last_exception_obj, thread_list):
    frame_map = {}
    used_images_map = {}

    target_frames = []
    if last_exception_obj:
        frames = last_exception_obj.frames
        target_frames.extend(frames)

    for thread in thread_list:
        target_frames.extend(thread.frames)

    for frame in target_frames:
        if not g_options.force_resymbolize and frame.symbol_name:
            continue

        image_name = frame.image_name
        if image_name == '???':
            continue

        image_info = g_name_info_map[image_name]
        uuid = image_info[0]
        # 根据uuid找符号文件
        if not used_images_map.get(image_name):
            used_images_map[image_name] = image_info

        frame_list = frame_map.get(uuid)
        if not frame_list:
            frame_list = []
            frame_map[uuid] = frame_list

        frame_list.append(frame)

    sym_paths = get_symbol_dir_paths()
    usse_images = used_images_map.values()
    print('--共有{}个image需要符号化'.format(len(usse_images)))
    print('--开始查找符号文件')
    fetch_symbolled_binaries(usse_images, sym_paths)
    print('--开始符号化')
    uuids = g_symbols_cache.keys()
    for uuid in frame_map:
        frame_list = frame_map[uuid]
        addr_list = [frame.load_addr for frame in frame_list]
        if len(addr_list) == 0:
            continue

        if uuid not in uuids:
            continue

        sym_path, arch = g_symbols_cache.get(uuid)
        if arch:
            # run atos
            print('符号化 {} {}个符号'.format(os.path.basename(sym_path), len(addr_list)))
            symbols = symbolize_frames(frame_list[0].base, addr_list, sym_path, arch)
            if len(symbols) == 0:
                continue

            for idx, frame in enumerate(frame_list):
                symbol_name, symbol_offset = symbols[idx]
                frame.symbol_name = symbol_name
                frame.symbol_offset = symbol_offset


def get_symbol_dir_paths():
    hw_model = g_crash_info.device_model
    os_version = g_crash_info.os_version
    os_build = g_crash_info.os_build
    # We don't match on 'os_version *' because it matches across device families.
    home_dir = os.path.expanduser('~')
    patterns = [
        f'{home_dir}/Library/Developer/Xcode/*DeviceSupport/{hw_model} {os_version} ({os_build})/Symbols*',
        f'{home_dir}/Library/Developer/Xcode/*DeviceSupport/{hw_model} {os_version} ({os_build}) */Symbols*',
        f'{home_dir}/Library/Developer/Xcode/*DeviceSupport/{os_version} ({os_build})/Symbols*',
        f'{home_dir}/Library/Developer/Xcode/*DeviceSupport/{os_version} ({os_build}) */Symbols*',
        f'{home_dir}/Library/Developer/Xcode/*DeviceSupport/{os_version}/Symbols*',
        f'{home_dir}/Library/Developer/Xcode/*DeviceSupport/{os_build}/Symbols*',
        f'{home_dir}/Library/Developer/Xcode/*DeviceSupport/{os_build} */Symbols*'
    ]

    file_paths = []
    for idx, pattern in enumerate(patterns):
        paths = glob.glob(pattern)
        if len(paths):
            contains_arch = idx == 1 or idx == 3
            for path in paths:
                if contains_arch:
                    architectures = "armv[4-8][tfsk]?|arm64\\S*|i386|x86_64\\S?"
                    arch_result = match_pattern(path, architectures)
                    arch = arch_result.split('/')[0]
                else:
                    arch = ''

                file_paths.append((path, arch))

    # 目前的Xcode中没有符号文件
    # code, xcode_paths_str, error = exe_shell_command('mdfind '
    #                                                  '"kMDItemCFBundleIdentifier == \'com.apple.dt.Xcode\' '
    #                                                  '|| kMDItemCFBundleIdentifier == \'com.apple.Xcode\'"')
    # if len(xcode_paths_str) > 0:
    #     xcode_paths = xcode_paths_str.split('\n')
    #     rel_paths = [
    #         f'Contents/Developer/Platforms/*.platform/DeviceSupport/{hw_model} {os_version} ({os_build})/Symbols*',
    #         f'Contents/Developer/Platforms/*.platform/DeviceSupport/{hw_model} {os_version} ({os_build}) */Symbols*',
    #         f'Contents/Developer/Platforms/*.platform/DeviceSupport/{os_version} ({os_build})/Symbols*',
    #         f'Contents/Developer/Platforms/*.platform/DeviceSupport/{os_version} ({os_build}) */Symbols*',
    #         f'Contents/Developer/Platforms/*.platform/DeviceSupport/{os_version}/Symbols*',
    #         f'Contents/Developer/Platforms/*.platform/DeviceSupport/{os_build}/Symbols*',
    #         f'Contents/Developer/Platforms/*.platform/DeviceSupport/{os_build} */Symbols*'
    #     ]
    #
    #     for xcode_path in xcode_paths:
    #         if len(xcode_path) == 0:
    #             continue
    #
    #         for rel_path in rel_paths:
    #             path_pattern = '{}/{}'.format(xcode_path, rel_path)
    #             paths = glob.glob(path_pattern)
    #             if len(paths):
    #                 file_paths.extend(paths)

    return file_paths


def fetch_symbolled_binaries(images, search_paths):
    not_found_list = []
    for uuid, path, target_arch, is_user_image in images:
        cached_obj = g_symbols_cache.get(uuid)
        if not cached_obj:
            image_name = os.path.basename(path)
            if g_options.verbose:
                print('begin find symbol for {} {}'.format(image_name, '=' * 80))
            sym_path = get_symbol_path_for(path, uuid, target_arch, is_user_image, search_paths)
            if sym_path:
                g_symbols_cache[uuid] = (sym_path, target_arch)
            else:
                not_found_list.append(image_name)

    print('--结束查找符号文件')
    for image_name in not_found_list:
        print('symbol file for {} not found'.format(image_name))


def get_symbol_path_for(path, uuid, target_arch, is_user_image, search_paths):
    sym_path = None

    # Look in any of the manually-passed dSYMs
    if is_user_image:
        manually_dysm = g_options.dsym.replace("'", "").replace('"', '').replace('\\', '')
        if len(manually_dysm):
            if g_options.verbose:
                print('lookup in manually-passed dSYMs:')
            sym_path = get_symbol_path_for_manual_dsym(manually_dysm, uuid, target_arch)

    # Look in the search paths (e.g. the device support directories)
    if not is_user_image:
        if g_options.verbose:
            print('lookup in the search paths:')
        sym_path = get_symbol_path_from_search_paths(path, uuid, target_arch, search_paths)

    if not sym_path:
        # Ask spotlight
        if g_options.verbose:
            print('ask spotlight:')
        sym_path = get_symbol_path_for_dsym_uuid(uuid, target_arch)

    return sym_path


def get_symbol_path_for_manual_dsym(dsym, uuid, target_arch):
    sym_path = None
    if not os.path.exists(dsym):
        if g_options.verbose:
            print('    file not found {}'.format(dsym))
        return sym_path

    dsym_machos = []
    if os.path.isfile(dsym):
        dsym_machos.append(dsym)
    elif dsym.endswith('.dSYM'):
        pattern = '{}/Contents/Resources/DWARF/*'.format(dsym)
        paths = glob.glob(pattern)
        if len(paths):
            dsym_machos.extend(paths)
        else:
            if g_options.verbose:
                print('    No symbol files found in {}'.format(dsym))
    else:
        filenames = os.listdir(dsym)
        for filename in filenames:
            if not filename.endswith('.dSYM'):
                continue

            sym_dir = os.path.join(dsym, filename)
            sym_path = get_symbol_path_for_manual_dsym(sym_dir, uuid, target_arch)
            if sym_path:
                break

    # Check the uuid's of each of the found files
    for file_path in dsym_machos:
        matched = sym_file_contains_uuid(file_path, uuid, target_arch)
        if matched:
            sym_path = file_path
            break

    return sym_path


def get_symbol_path_from_search_paths(path, uuid, target_arch, search_paths):
    sym_path = None
    for search_path, sym_arch in search_paths:
        if len(sym_arch) and sym_arch != target_arch:
            continue

        # path前自带分隔符，不需要添加分隔符
        sym_file_path = '{}{}'.format(search_path, path)
        matched = sym_file_contains_uuid(sym_file_path, uuid, target_arch)
        if matched:
            sym_path = sym_file_path
            break

    return sym_path


def get_symbol_path_for_dsym_uuid(uuid, target_arch):
    """
    mdfind只搜索~/Library/Developer/Xcode/Archives，且路径到.xcarchive为止
    结果示例：
    $ mdfind "com_apple_xcode_dsym_uuids == *"
    /Users/xxx/Library/Developer/Xcode/Archives/2024-07-24/TestDemo 2024-7-24, 13.57.xcarchive
    ...
    /Users/xxx/Library/Developer/Xcode/Archives/2024-05-29/Demo 2024-5-29, 13.31.xcarchive
    """
    sym_path = None

    cmd = 'mdfind \"com_apple_xcode_dsym_uuids == \'{}\'\"'.format(uuid)
    code, mdfind_result, err = exe_shell_command(cmd)
    if len(mdfind_result) == 0:
        return sym_path

    xcarchives = mdfind_result.split('\n')

    dsym_paths = []
    for xcarchive in xcarchives:
        if len(xcarchive) == 0:
            continue

        cmd = 'mdls -name com_apple_xcode_dsym_paths \'{}\''.format(xcarchive)
        code, mdls_result, err = exe_shell_command(cmd)
        dsym_dirs_str = match_bracket(mdls_result, True)
        dsym_dirs = dsym_dirs_str.split('\n')
        for dsym_dir in dsym_dirs:
            if len(dsym_dir) == 0:
                continue

            rel_path = dsym_dir.strip().replace('",', '').replace('"', '')
            dsym_paths.append('{}{}{}'.format(xcarchive, os.path.sep, rel_path))

    for dsym_path in dsym_paths:
        matched = sym_file_contains_uuid(dsym_path, uuid, target_arch)
        if matched:
            sym_path = dsym_path
            break

    return sym_path


def sym_file_contains_uuid(sym_file_path, uuid, target_arch):
    matched = False

    cmd = f"otool -arch {target_arch} -l '{sym_file_path}' | grep -E 'uuid|nlocalsym|nextdefsym|segname __DWARF'"
    if g_options.verbose:
        print('    {}'.format(cmd))
    code, otool_result, err = exe_shell_command(cmd)
    if len(otool_result) == 0:
        return matched

    lines = otool_result.split('\n')
    contains_uuid = False
    is_dsym = False
    n_total_sym = 0
    for line in lines:
        if 'uuid' in line:
            contains_uuid = uuid in line
        elif 'nlocalsym ' in line:
            nlocalsym = line.replace('nlocalsym', '').strip()
            n_total_sym += int(nlocalsym)
        elif 'nextdefsym ' in line:
            nextdefsym = line.replace('nextdefsym', '').strip()
            n_total_sym += int(nextdefsym)
        elif '__DWARF' in line:
            is_dsym = True
            break

    return contains_uuid and (is_dsym or n_total_sym > 1)


def symbolize_frames(base_addr, addr_list, sym_path, arch):
    addr_str_list = ['{:#x}'.format(addr) for addr in addr_list]
    cmd = 'atos -arch {} -l {:#x} -o \'{}\' {}'.format(arch, base_addr, sym_path, ' '.join(addr_str_list))
    code, atos_result, err = exe_shell_command(cmd)

    symbol_list = atos_result.split('\n')

    symbols = []
    for symbol_line in symbol_list:
        if len(symbol_line) == 0:
            continue

        if ' + ' in symbol_line:
            comps = symbol_line.split(' + ')
            if len(comps) != 2:
                print(symbol_line)

            sym_name = comps[0]
            offset = comps[1]
        else:
            sym_name = symbol_line
            # main (in JITDemo) (main.m:17)，不包含offset
            offset = -1

        sym_name = sym_name.replace(' (in {})'.format(os.path.basename(sym_path)), '')
        # atos处理中文镜像名存在问题
        sym_name = sym_name.replace(' (in )', '')
        symbols.append((sym_name, offset))

    return symbols


class Frame:
    idx = -1
    image_name = ''
    max_width = 0  # max width of image name
    load_addr = 0
    base = 0
    file_offset = 0
    symbol_name = ''
    symbol_offset = 0

    def description(self):
        frame_des = ''
        if len(self.symbol_name) > 0:
            name_or_addr = self.symbol_name
            offset = self.symbol_offset
        else:
            name_or_addr = '{:#x}'.format(self.base)
            offset = self.file_offset

        if self.max_width == 0:
            self.max_width = g_max_name_width

        if self.image_name == '???':
            frame_des += '{:<4}{:<{}}  {:#x} ???\n'. \
                format(self.idx, self.image_name, self.max_width, self.load_addr)
        # atos有时不输出offset
        elif offset == -1:
            frame_des += '{:<4}{:<{}}  {:#x} {}\n'. \
                format(self.idx, self.image_name, self.max_width, self.load_addr, name_or_addr)
        else:
            frame_des += '{:<4}{:<{}}  {:#x} {} + {}\n'. \
                format(self.idx, self.image_name, self.max_width, self.load_addr, name_or_addr, offset)

        return frame_des


class Thread:
    title = ''
    frames: [Frame] = []

    def description(self):
        thread_des = '{}'.format(self.title)
        for frame in self.frames:
            thread_des += '{}'.format(frame.description())

        return thread_des


def match_os_version(input_str):
    os_version = match_pattern(input_str, r'(\d+)\.(\d+)\.(\d+)')
    if not os_version:
        print(f'Version {input_str} did not match.')
        os_version = ''

    return os_version


def match_pattern(input_str, pattern):
    pattern_obj = re.compile(pattern)
    result = pattern_obj.search(input_str)
    if result:
        match_result = result.group()
    else:
        match_result = ''

    return match_result


def match_os_build(input_str):
    os_build = match_bracket(input_str, True)
    if len(os_build) == 0:
        print(f"Build {input_str} did not match.")
        os_build = ''

    return os_build


def match_bracket(input_str, bare=False):
    # 匹配()，其中的内容包含换行符在内的任意字符
    build_pattern = re.compile(r'\((.*?)\)', re.DOTALL)
    result = build_pattern.search(input_str)
    if result:
        if bare:
            match_result = result.group(1)
        else:
            match_result = result.group()
    else:
        match_result = ''

    return match_result


def get_canonical_uuid_for_uuid(uuid):
    pattern_obj = re.compile(r'(.{8})(.{4})(.{4})(.{4})(.{12})')
    result = pattern_obj.search(uuid)
    if result:
        canonical_uuid = '{}-{}-{}-{}-{}'.format(result.group(1),
                                                 result.group(2),
                                                 result.group(3),
                                                 result.group(4),
                                                 result.group(5))
    else:
        canonical_uuid = uuid

    return canonical_uuid


def exe_shell_command(cmd, cwd=None):
    """
    执行命令，截获控制台输出
    """
    if "/usr/local/bin" not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + "/usr/local/bin/"

    comps = cmd.split(' ')
    prog = comps[0]
    if subprocess.call(["/usr/bin/which", prog], shell=False, stdout=subprocess.PIPE) != 0:
        return -1, '', '{} not found'.format(prog)

    prog_path = subprocess.Popen(['/usr/bin/which', prog],
                                 shell=False,
                                 stdout=subprocess.PIPE).communicate()[0].rstrip(b'\n\r').decode()
    prog_path = prog_path.replace('//', '/')
    new_cmd = cmd.replace(prog, prog_path, 1)

    obj = subprocess.Popen(new_cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = obj.communicate()
    code = obj.wait()

    return code, out.decode(), err.decode()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Symbolize /path/to/crash/report/file')
    parser.add_argument('file', nargs='?', help='path to crash report file')
    parser.add_argument("-f", "--force",
                        action='store_true',
                        default=False,
                        dest="force",
                        help="force resymbolize")
    parser.add_argument("-v", "--verbose",
                        action='store_true',
                        default=False,
                        dest="verbose",
                        help="show verbose log")
    parser.add_argument("-d", "--dsym",
                        dest="dsym",
                        help="path to dsym or directory of dsym(s) for user module(s)")

    args = parser.parse_args()

    exit_code = 0

    if not args.file:
        parser.print_help()
        sys.exit(exit_code)

    input_path = args.file.replace('"', '').replace("'", '')
    if not os.path.exists(input_path):
        print('No such file or directory: {}'.format(input_path))
        sys.exit(exit_code)

    if args.force:
        g_options.force_resymbolize = True

    if args.verbose:
        g_options.verbose = True

    if args.dsym:
        g_options.dsym = args.dsym
    else:
        g_options.dsym = os.path.dirname(input_path)

    crash_report_paths = []
    if input_path.endswith('.ips') or input_path.endswith('.crash'):
        if not args.dsym:
            g_options.dsym = os.path.dirname(input_path)
        crash_report_paths.append(input_path)
    elif os.path.isdir(input_path):
        if not args.dsym:
            g_options.dsym = input_path

        names = os.listdir(input_path)
        for name in names:
            if name.endswith('.ips') or (name.endswith('.crash') and not name.endswith('.sym.crash')):
                crash_report_path = os.path.join(input_path, name)
                crash_report_paths.append(crash_report_path)
    else:
        print('unknown argument')
        sys.exit(exit_code)

    message = '\n\n符号化的崩溃日志:\n'
    for crash_report_path in crash_report_paths:
        print('开始符号化：{}'.format(crash_report_path))
        crash_report = symbolize_crash_report(crash_report_path)
        ext = os.path.splitext(crash_report_path)[1]

        output_file = crash_report_path.replace(ext, '.sym.crash')
        with open(output_file, 'w') as x_file:
            written_size = x_file.write(crash_report)

            if written_size == len(crash_report):
                message += '    {}\n'.format(output_file)
            else:
                message += '    崩溃日志存储失败：\n{}'.format(crash_report)

            x_file.close()

    print(message)
