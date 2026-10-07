import hashlib
import io
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scan_lut_xrefs import adrp, add_immediate
from scan_direct_calls import branch_target
from scan_thumb_calls import branch_target as thumb_branch_target, scan as scan_thumb_calls
from emulate_picture_gate import EXPECTED_SHA256, PictureGate, run_matrix
from emulate_cp_receiver import run_receiver
from emulate_cp_pipeline import Pipeline, run_matrix as run_cp_matrix
from emulate_mlut_handoff import run_handoff
from emulate_mlut_routing import run_routing, run_initial_mapping
from inspect_camera_info_bridge import inspect as inspect_camera_info_bridge
from emulate_mlut_driver_request import DriverRequest, run_matrix as run_driver_matrix
from emulate_l3d_descriptors import DescriptorBuilder, run_matrix as run_descriptor_matrix
from emulate_mlut_resource_mapping import ResourceMapping, run_matrix as run_resource_matrix
from emulate_mlut_resource_allocation import run_matrix as run_allocation_matrix
from emulate_mlut_token_flow import run_matrix as run_token_matrix
from emulate_mlut_stream_resources import run_matrix as run_stream_matrix
from emulate_stream_config_selection import run_matrix as run_config_selection_matrix
from elftools.elf.elffile import ELFFile

RESEARCH = Path(__file__).resolve().parents[1]
BINARY = RESEARCH / 'a7c2-2.01/selected/files/lib/appFw.so'


class Decoders(unittest.TestCase):
    def test_adrp_real_instruction(self):
        self.assertEqual(adrp(0xf000ba94, 0x352c71c), (20, 0x4c7f000))

    def test_adrp_negative(self):
        self.assertEqual(adrp(0xf0ffffe0, 0x1000), (0, 0))

    def test_add(self):
        self.assertEqual(add_immediate(0x91352294), (20, 20, 0xd48))
        self.assertIsNone(add_immediate(0x11000400))  # W-register ADD is not a 64-bit pointer.

    def test_branch(self):
        self.assertEqual(branch_target(0x97ffd16e, 0x3538024), ('BL', 0x352c5dc))
        self.assertIsNone(branch_target(0xd65f03c0, 0x1000))

    def test_thumb_branch_forward_and_backward(self):
        self.assertEqual(thumb_branch_target(0xf029, 0xf9b1, 0x4bf6f6), ('BL', 0x4e8a5c))
        self.assertEqual(thumb_branch_target(0xf5bc, 0xf2e0, 0xb2c498), ('BL', 0x4e8a5c))
        self.assertEqual(thumb_branch_target(0xf000, 0xb800, 0x1000), ('B.W', 0x1004))
        self.assertIsNone(thumb_branch_target(0x4770, 0, 0x1000))
        self.assertIsNone(thumb_branch_target(0xf000, 0x8000, 0x1000))

    def test_thumb_scan_decodes_and_checks_pointer(self):
        data = bytes.fromhex('29f0b1f9') + struct.pack('<I', 0x4e8a5d)
        evidence = scan_thumb_calls(data, 0x4bf6f6, [0x4e8a5c])['0x4e8a5c']
        self.assertEqual(evidence['calls'][0]['va'], '0x4bf6f6')
        self.assertEqual(evidence['pointers'], ['0x4bf6fa'])


class ArtifactChecks(unittest.TestCase):
    def test_input_hash(self):
        self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), EXPECTED_SHA256)

    def test_ghidra_code_matches_original_elf(self):
        data = BINARY.read_bytes()
        elf = ELFFile(io.BytesIO(data))
        for line in (RESEARCH / 'lut-functions.tsv').read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            start, end, name = line.split()
            start, end = int(start, 16), int(end, 16)
            segment = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                           and s['p_vaddr'] <= start < end <= s['p_vaddr'] + s['p_filesz'])
            offset = start - segment['p_vaddr'] + segment['p_offset']
            artifact = RESEARCH / f'a7c2-2.01/decompiled/{start:08x}_{name}.bytes.hex'
            self.assertEqual(bytes.fromhex(artifact.read_text()), data[offset:offset+end-start], name)

    def test_original_helper_matrix(self):
        self.assertEqual(run_matrix(BINARY)['passed_cases'], 68)

    def test_cp_ghidra_code_matches_raw_binary(self):
        data = (RESEARCH / 'a7c2-2.01/cp-selected/files/cpapp-b.bin').read_bytes()
        for line in (RESEARCH / 'cp-functions.tsv').read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            start, end, name = line.split()
            start, end = int(start, 16), int(end, 16)
            artifact = RESEARCH / f'a7c2-2.01/cp-decompiled/{start:08x}_{name}.bytes.hex'
            self.assertEqual(bytes.fromhex(artifact.read_text()), data[start-0x108000:end-0x108000], name)

    def test_mode_is_decisive_with_same_inputs(self):
        emulator = PictureGate(BINARY)
        self.assertEqual(emulator.run(mode=0)[:2], [11, 3])
        self.assertEqual(emulator.run(mode=1)[:2], [10, 0])

    def test_cp_receiver_and_dispatch(self):
        for payload in ([11, 3, 0, 1, 0], [10, 0, 0, 1, 0], [7, 2, 1, 0, 0]):
            self.assertEqual(run_receiver(payload)['return_value'], 1)

    def test_cp_receiver_builder_matrix(self):
        report = run_cp_matrix()
        self.assertEqual(report['passed_cases'], 768)

    def test_cp_second_gate_and_descriptor(self):
        emulator = Pipeline()
        disabled = emulator.run(shooting_mode=3)
        self.assertEqual((disabled['effective_base_look'], disabled['mlut_id']), (11, 0))
        self.assertEqual(disabled['path_flags'], [0]*4)
        missing = emulator.run(descriptor_word=0)
        self.assertEqual(missing['effective_base_look'], 0)
        self.assertFalse(missing['descriptor_copied'])
        candidate = emulator.run()
        self.assertEqual(candidate['effective_base_look'], 10)
        self.assertTrue(candidate['descriptor_copied'])
        self.assertEqual(candidate['path_flags'], [1]*4)

    def test_mlut_handoff_l3d_only(self):
        result = run_handoff(0, 0)
        self.assertEqual(result['stop_pc'], '0x54e15c')
        self.assertEqual(result['handoff']['l3d']['size'], 1)
        self.assertIsNone(result['handoff']['reg'])
        self.assertFalse(result['lower_function_executed'])

    def test_mlut_handoff_l3d_and_reg(self):
        result = run_handoff(0, 1)
        self.assertEqual(result['stop_pc'], '0x54e398')
        self.assertEqual(result['handoff']['reg']['size'], 1)
        self.assertEqual(result['handoff']['callback'], '0x4e89f1')

    def test_mlut_disabled_does_not_handoff(self):
        self.assertIsNone(run_handoff(3, 1)['handoff'])

    def test_mlut_flag_routing_and_branch(self):
        result = run_routing([0, 1, 0, 1], [3, 2, 1, 0])
        self.assertEqual(result['routed_flags'], [1, 0, 1, 0])
        self.assertEqual([d['enter_mlut_configuration'] for d in result['decisions']], [True, False, True, False])

    def test_mlut_zero_flags_skip_configuration(self):
        result = run_routing([0, 0, 0, 0], [0, 1, 2, 3])
        self.assertTrue(all(d['stop_pc'] == '0x4e0df0' for d in result['decisions']))

    def test_original_mapping_initializer(self):
        self.assertEqual(run_initial_mapping(False)['mapping'], [0, 1, 2, 3])
        self.assertEqual(run_initial_mapping(True)['mapping'], [0, 0, 0, 0])

    def test_shared_mapping_replicates_first_flag(self):
        mapping = run_initial_mapping(True)['mapping']
        self.assertEqual(run_routing([1, 0, 0, 0], mapping)['routed_flags'], [1]*4)
        self.assertEqual(run_routing([0, 1, 1, 1], mapping)['routed_flags'], [0]*4)

    def test_camera_info_cross_architecture_evidence(self):
        report = inspect_camera_info_bridge()
        self.assertEqual(report['cp']['rtti']['encoded_name'], report['av_cam']['rtti']['encoded_name'])
        self.assertEqual(report['reviewed_match']['payload_size'], 936)
        callers = report['av_cam']['candidate_direct_callers']['0xa437c']
        self.assertIn({'offset': '0x14796c', 'kind': 'BL'}, callers)
        self.assertIn({'offset': '0x1482e4', 'kind': 'BL'}, callers)

    def test_original_mlut_driver_boundaries(self):
        self.assertEqual(run_driver_matrix()['passed_cases'], 90)

    def test_mlut_driver_request_dispatch(self):
        emulator = DriverRequest()
        self.assertEqual(emulator.run('l3d', 0, 48000)['manual_dispatch_target'], '0xb82d7c')
        self.assertEqual(emulator.run('reg', 6, 124)['manual_dispatch_target'], '0xb82e00')
        self.assertEqual(emulator.run('l3d', 7, 48000)['return_signed'], -13)

    def test_l3d_descriptor_matrix(self):
        self.assertEqual(run_descriptor_matrix()['passed_cases'], 14)

    def test_resource_mapping_matrix(self):
        self.assertEqual(run_resource_matrix()['passed_cases'], 35)

    def test_resource_allocation_resolution(self):
        self.assertEqual(run_allocation_matrix()['passed_cases'], 28)

    def test_resource_token_store_and_submit_arguments(self):
        self.assertEqual(run_token_matrix()['passed_cases'], 16)

    def test_stream_resource_mapping(self):
        report = run_stream_matrix()
        self.assertEqual(report['executed_nonempty_lookups'], 7)
        self.assertEqual([row['resources'] for row in report['rows']],
                         [[23], [30], [37], [44], [23, 30], [37, 44], [23, 30, 37, 44], [], [], []])
        self.assertEqual(report['resource_names'], {'23': 'GRP05_VFX', '30': 'GRP06_VFX',
                                                  '37': 'GRP07_VFX', '44': 'GRP08_VFX'})

    def test_stream_configuration_selection(self):
        self.assertEqual(run_config_selection_matrix()['passed_cases'], 32)

    def test_capture_resource_type_and_acquire_calls(self):
        data = (RESEARCH / 'a7c2-2.01/cp-selected/files/cpapp-b.bin').read_bytes()
        def word(address):
            return struct.unpack_from('<I', data, address-0x108000)[0]
        def cstring(address):
            return data[address-0x108000:].split(b'\0', 1)[0]
        self.assertEqual(word(0xe769e4), 0x4811dd)
        self.assertEqual(word(0xe769d8), 0xe76a10)
        self.assertEqual(cstring(word(0xe76a14)), b'N6Camera7Capture11CapRsrc_VFXE')
        self.assertEqual(cstring(0x48131c), b'AcquireMain')
        self.assertEqual(cstring(0xfbf70a), b'CapRsrc_VFX.cpp')
        for address, target in ((0x481228, 0x54d05c), (0x481256, 0xbb2a78)):
            h1, h2 = struct.unpack_from('<HH', data, address-0x108000)
            self.assertEqual(thumb_branch_target(h1, h2, address), ('BL', target))

    def test_resource_mapping_groups_and_rejection(self):
        emulator = ResourceMapping()
        self.assertEqual(emulator.run(0, [(0x123, 1)]*4)['ip'], 4)
        self.assertEqual(emulator.run(0, [(0x123, 1)]*2 + [(0x456, 1)]*2)['ip'], 5)
        rejected = emulator.run(0, [(0x123, 1), (0x456, 1)]*2)
        self.assertEqual(rejected['status'], 5)
        self.assertTrue(rejected['output_untouched'])

    def test_l3d_control_table_evidence(self):
        result = DescriptorBuilder().run(0)
        self.assertEqual(result['descriptor_count'], 48)
        self.assertIsNone(result['records'][0]['control_value_from_file'])
        for i, record in enumerate(result['records'][1:], 1):
            self.assertEqual(record['control_value_from_file'], (i % 8)*16 + i//8)


if __name__ == '__main__':
    unittest.main()
