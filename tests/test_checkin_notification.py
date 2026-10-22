import asyncio
from unittest.mock import Mock, patch

import pytest

from checkin import format_check_in_notification, generate_balance_hash, main


def test_format_success_notification():
	message = format_check_in_notification(
		{
			'name': '测试账号',
			'status': 'SUCCESS',
			'success': True,
			'check_in_reward': 12.5,
			'after_quota': 100.0,
			'after_used': 20.0,
		}
	)

	assert message == '\n'.join(
		[
			'【成功】测试账号',
			'  签到增加额度：+$12.50',
			'  现有额度：$100.00',
			'  已消耗额度：$20.00',
		]
	)


def test_check_in_without_quota_is_reported_as_partial():
	account = Mock()
	account.get_display_name.return_value = '测试账号'
	accounts = [account]

	with (
		patch('checkin.AppConfig.load_from_env', return_value=Mock(providers={})),
		patch('checkin.load_accounts_config', return_value=accounts),
		patch('checkin.load_balance_hash', return_value=None),
		patch(
			'checkin.check_in_account',
			return_value=(True, None, {'success': False, 'error': '额度接口超时'}),
		),
		patch('checkin.take_pending_screenshots', return_value=[]),
		patch('checkin.notify.push_message') as push_message,
		pytest.raises(SystemExit) as exit_info,
	):
		asyncio.run(main())

	assert exit_info.value.code == 0
	title, content = push_message.call_args.args[:2]
	assert title == 'AnyRouter 签到汇总'
	assert '【成功（额度未获取）】测试账号' in content
	assert '  提示：额度接口超时' in content
	assert '成功：1/1' in content
	assert '结果：全部账号签到成功' in content


@pytest.fixture
def run_checkin():
	def run(results, last_hash=None, names=None):
		accounts = []
		for i in range(len(results)):
			account = Mock()
			account.get_display_name.return_value = names[i] if names else f'测试账号{i + 1}'
			accounts.append(account)

		with (
			patch('checkin.is_debug_enabled', return_value=False),
			patch('checkin.AppConfig.load_from_env', return_value=Mock(providers={})),
			patch('checkin.load_accounts_config', return_value=accounts),
			patch('checkin.load_balance_hash', return_value=last_hash),
			patch('checkin.save_balance_hash') as save_hash,
			patch('checkin.check_in_account', side_effect=results),
			patch('checkin.notify.push_message') as push_message,
			pytest.raises(SystemExit) as exit_info,
		):
			asyncio.run(main())

		return exit_info.value.code, push_message, save_hash

	return run


@pytest.mark.parametrize(
	('result', 'expected_lines', 'exit_code'),
	[
		(
			(
				True,
				{'success': True, 'quota': 100.0, 'used_quota': 20.0},
				{'success': True, 'quota': 110.0, 'used_quota': 25.0},
			),
			['【成功】测试账号1', '签到增加额度：+$15.00', '现有额度：$110.00', '已消耗额度：$25.00'],
			0,
		),
		(
			(True, None, {'success': True, 'quota': 110.0, 'used_quota': 25.0}),
			['【成功】测试账号1', '签到增加额度：暂不可用', '现有额度：$110.00', '已消耗额度：$25.00'],
			0,
		),
		(
			(
				True,
				{'success': True, 'quota': 110.0, 'used_quota': 25.0},
				{'success': True, 'quota': 110.0, 'used_quota': 25.0},
			),
			['【成功】测试账号1', '签到增加额度：+$0.00'],
			0,
		),
		(
			(
				False,
				{'success': True, 'quota': 100.0, 'used_quota': 20.0},
				{'success': True, 'quota': 110.0, 'used_quota': 25.0},
			),
			[
				'【失败】测试账号1',
				'签到增加额度：暂不可用',
				'现有额度：$110.00',
				'已消耗额度：$25.00',
				'失败原因：签到失败，请查看运行日志',
			],
			1,
		),
		(
			(False, None, {'success': False, 'error': '登录已过期'}),
			['【失败】测试账号1', '失败原因：登录已过期'],
			1,
		),
		(
			(False, None, None),
			['【失败】测试账号1', '失败原因：签到失败，请查看运行日志'],
			1,
		),
		(
			RuntimeError('请求异常'),
			['【失败】测试账号1', '失败原因：处理异常，请查看运行日志'],
			1,
		),
	],
)
def test_account_results_include_correct_status_and_quota(run_checkin, result, expected_lines, exit_code):
	code, push_message, _ = run_checkin([result])
	assert code == exit_code
	push_message.assert_called_once()
	title, content = push_message.call_args.args[:2]
	assert title == 'AnyRouter 签到汇总'
	for line in expected_lines:
		assert line in content
	if exit_code == 0:
		assert '签到失败' not in content
		assert '失败：0/1' in content
	else:
		assert '失败：1/1' in content


def test_mixed_results_include_all_accounts_even_with_duplicate_names(run_checkin):
	results = [
		(
			True,
			{'success': True, 'quota': 100.0, 'used_quota': 20.0},
			{'success': True, 'quota': 110.0, 'used_quota': 25.0},
		),
		(False, None, None),
	]
	code, push_message, _ = run_checkin(results, names=['相同名称', '相同名称'])
	assert code == 0
	content = push_message.call_args.args[1]
	assert '【成功】相同名称' in content
	assert '【失败】相同名称' in content
	assert content.count('签到增加额度：') == 2
	assert content.count('现有额度：') == 2
	assert content.count('已消耗额度：') == 2
	assert '成功：1/2' in content
	assert '失败：1/2' in content
	assert '结果：部分账号签到成功' in content


def test_success_with_unchanged_balances_skips_notification(run_checkin):
	user_info = {'success': True, 'quota': 100.0, 'used_quota': 20.0}
	last_hash = generate_balance_hash({'account_1': {'quota': 100.0, 'used': 20.0}})
	code, push_message, save_hash = run_checkin([(True, user_info, user_info)], last_hash)
	assert code == 0
	push_message.assert_not_called()
	save_hash.assert_called_once_with(last_hash)
