import asyncio
import time
import json

from indy import anoncreds, crypto, did, ledger, pool, wallet

tab = "    "

async def run():

    print("============== Start Demo ==============")

    print("Setup Pool")
    await pool.set_protocol_version(2) # Set protocol version 2 to work with Indy Node 1.4
    pool_ = {
        'name': 'pool1',
        'config': json.dumps({"genesis_txn": '/home/indy/sandbox/pool_transactions_genesis'})
    }
    print(tab + "Create pool")
    try:
        await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    print(tab + "Get pool handle")
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print("Setup Government")
    government = {
        'name': "government",
        'wallet_config': json.dumps({'id': 'government_wallet'}),
        'wallet_credentials': json.dumps({'key': 'government_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }
    print(tab + "Create wallet")
    try:
        await wallet.create_wallet(government['wallet_config'], government['wallet_credentials'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass
    government['wallet'] = await wallet.open_wallet(government['wallet_config'], government['wallet_credentials'])
    government['did_info'] = json.dumps({'seed': government['seed']})
    print(tab + "Create and store did and key in wallet")
    government['did'], government['key'] = await did.create_and_store_my_did(government['wallet'], government['did_info'])

    print("==============================")
    print("==============================")

    print("Onboard SEC")
    sec = {
        'name': 'sec',
        'wallet_config': json.dumps({'id': 'sec_wallet'}),
        'wallet_credentials': json.dumps({'key': 'sec_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    government['did_for_sec'], government['key_for_sec'], sec['did_for_government'], sec['key_for_government'], _ = await onboarding(government, sec)
    sec['did'] = await get_verinym(government, sec)

    print("Onboard General Auditor")
    general_auditor = {
        'name': 'general_auditor',
        'wallet_config': json.dumps({'id': 'general_auditor_wallet'}),
        'wallet_credentials': json.dumps({'key': 'general_auditor_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    government['did_for_general_auditor'], government['key_for_general_auditor'], general_auditor['did_for_government'], general_auditor['key_for_government'], _ = await onboarding(government, general_auditor)
    general_auditor['did'] = await get_verinym(government, general_auditor)

    print("Onboard Financial Auditor")
    financial_auditor = {
        'name': 'financial_auditor',
        'wallet_config': json.dumps({'id': 'financial_auditor_wallet'}),
        'wallet_credentials': json.dumps({'key': 'financial_auditor_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    government['did_for_financial_auditor'], government['key_for_financial_auditor'], financial_auditor['did_for_government'], financial_auditor['key_for_government'], _ = await onboarding(government, financial_auditor)
    financial_auditor['did'] = await get_verinym(government, financial_auditor)

    print("Onboard Goldman Sachs")
    goldman_sachs = {
        'name': 'goldman_sachs',
        'wallet_config': json.dumps({'id': 'goldman_sachs_wallet'}),
        'wallet_credentials': json.dumps({'key': 'goldman_sachs_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    government['did_for_goldman_sachs'], government['key_for_goldman_sachs'], goldman_sachs['did_for_government'], goldman_sachs['key_for_government'], _ = await onboarding(government, goldman_sachs)
    goldman_sachs['did'] = await get_verinym(government, goldman_sachs)

    print("==============================")

    print("SEC -> Create General KYC Credential Schema")
    general_kyc = {
        'name': 'General KYC',
        'version': '1.2',
        'attributes': ['id']
    }
    (sec['general_kyc_schema_id'], sec['general_kyc_schema']) = await anoncreds.issuer_create_schema(sec['did'],
                                                                                                     general_kyc['name'],
                                                                                                     general_kyc['version'],
                                                                                                     json.dumps(general_kyc['attributes']))
    general_kyc_schema_id = sec['general_kyc_schema_id']

    print("SEC -> Send General KYC Credential Schema to Ledger")
    await send_schema(sec['pool'], sec['wallet'], sec['did'], sec['general_kyc_schema'])

    print("SEC -> Create Financial KYC Credential Schema")
    financial_kyc = {
        'name': 'Financial KYC',
        'version': '1.2',
        'attributes': ['rating']
    }
    (sec['financial_kyc_schema_id'], sec['financial_kyc_schema']) = await anoncreds.issuer_create_schema(sec['did'],
                                                                                                         financial_kyc['name'],
                                                                                                         financial_kyc['version'],
                                                                                                         json.dumps(financial_kyc['attributes']))
    financial_kyc_schema_id = sec['financial_kyc_schema_id']

    print("SEC -> Send Financial KYC Credential Schema to Ledger")
    await send_schema(sec['pool'], sec['wallet'], sec['did'], sec['financial_kyc_schema'])

    time.sleep(1) # sleep 1 second before getting schema

    print("==============================")

    print("General Auditor -> Get General KYC Schema from Ledger")
    (general_auditor['general_kyc_schema_id'], general_auditor['general_kyc_schema']) = await get_schema(general_auditor['pool'], general_auditor['did'], general_kyc_schema_id)

    print("General Auditor -> Create and Store General KYC Credential Definition in Wallet")
    general_kyc_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (general_auditor['general_kyc_cred_def_id'], general_auditor['general_kyc_cred_def']) = await anoncreds.issuer_create_and_store_credential_def(general_auditor['wallet'],
                                                                                                                                                   general_auditor['did'],
                                                                                                                                                   general_auditor['general_kyc_schema'],
                                                                                                                                                   general_kyc_cred_def['tag'],
                                                                                                                                                   general_kyc_cred_def['type'],
                                                                                                                                                   json.dumps(general_kyc_cred_def['config']))

    print("General Auditor -> Send General KYC Credential Definition to Ledger")
    await send_cred_def(general_auditor['pool'], general_auditor['wallet'], general_auditor['did'], general_auditor['general_kyc_cred_def'])

    print("Financial Auditor -> Get Financial KYC Schema from Ledger")
    (financial_auditor['financial_kyc_schema_id'], financial_auditor['financial_kyc_schema']) = await get_schema(financial_auditor['pool'], financial_auditor['did'], financial_kyc_schema_id)

    print("Financial Auditor -> Create and Store Financial KYC Credential Definition in Wallet")
    financial_kyc_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (financial_auditor['financial_kyc_cred_def_id'], financial_auditor['financial_kyc_cred_def']) = await anoncreds.issuer_create_and_store_credential_def(financial_auditor['wallet'],
                                                                                                                                                           financial_auditor['did'],
                                                                                                                                                           financial_auditor['financial_kyc_schema'],
                                                                                                                                                           financial_kyc_cred_def['tag'],
                                                                                                                                                           financial_kyc_cred_def['type'],
                                                                                                                                                           json.dumps(financial_kyc_cred_def['config']))

    print("Financial Auditor -> Send Financial KYC Credential Definition to Ledger")
    await send_cred_def(financial_auditor['pool'], financial_auditor['wallet'], financial_auditor['did'], financial_auditor['financial_kyc_cred_def'])

    print("==============================")

    print("==============================")
    print("==============================")

    print("Close and Delete Government\'s Wallet")
    await wallet.close_wallet(government['wallet'])
    await wallet.delete_wallet(government['wallet_config'], government['wallet_credentials'])

    print("Close and Delete SEC\'s Wallet")
    await wallet.close_wallet(sec['wallet'])
    await wallet.delete_wallet(sec['wallet_config'], sec['wallet_credentials'])

    print("Close and Delete General Auditor\'s Wallet")
    await wallet.close_wallet(general_auditor['wallet'])
    await wallet.delete_wallet(general_auditor['wallet_config'], general_auditor['wallet_credentials'])

    print("Close and Delete Financial Auditor\'s Wallet")
    await wallet.close_wallet(financial_auditor['wallet'])
    await wallet.delete_wallet(financial_auditor['wallet_config'], financial_auditor['wallet_credentials'])

    print("Close and Delete Goldman Sachs\'s Wallet")
    await wallet.close_wallet(goldman_sachs['wallet'])
    await wallet.delete_wallet(goldman_sachs['wallet_config'], goldman_sachs['wallet_credentials'])

    # print("Close and Delete JP Morgan\'s Wallet")
    # await wallet.close_wallet(jp_morgan['wallet'])
    # await wallet.delete_wallet(jp_morgan['wallet_config'], jp_morgan['wallet_credentials'])

    print("Close and Delete Pool")
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    print("============== Finish Demo ==============")


async def onboarding(_from, to):

    print('===== Generate Pseudonym =====')

    print(tab + _from['name'] + ' -> Create pairwise did and key for ' + to['name'] + ' and store in wallet')
    (from_to_did, from_to_key) = await did.create_and_store_my_did(_from['wallet'], "{}")

    print(tab + _from['name'] + ' -> Send the pairwise did and key to ledger')
    await send_nym(_from['pool'], _from['wallet'], _from['did'], from_to_did, from_to_key, None)

    print(tab + _from['name'] + ' -> Create connection request for ' + to['name'] + ' with the pairwise did and a nonce')
    _from['connection_request'] = {'did': from_to_did, 'nonce': 123456789}

    print(tab + _from['name'] + ' -> Send connection request to ' + to['name'])
    to['connection_request'] = _from['connection_request']

    print(tab + to['name'] + ' -> Create wallet')
    if 'wallet' not in to:
        try:
            await wallet.create_wallet(to['wallet_config'], to['wallet_credentials'])
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass
        to['wallet'] = await wallet.open_wallet(to['wallet_config'], to['wallet_credentials'])

    print(tab + to['name'] + ' -> Create pairwise did and key for ' + _from['name'] + ' and store in wallet')
    (to_from_did, to_from_key) = await did.create_and_store_my_did(to['wallet'], "{}")

    print(tab + to['name'] + ' -> Create connection response for ' + _from['name'] + ' with the pairwise did and key and the nonce')
    to['connection_response'] = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': to['connection_request']['nonce']
    })

    print(tab + to['name'] + ' -> Get pairwise key of ' + _from['name'] + ' from ledger')
    from_to_verkey = await did.key_for_did(_from['pool'], to['wallet'], to['connection_request']['did'])

    print(tab + to['name'] + ' -> Encrypt connection response with the pairwise key')
    to['anoncrypted_connection_response'] = await crypto.anon_crypt(from_to_verkey, to['connection_response'].encode('utf-8'))

    print(tab + to['name'] + ' -> Send connection response to ' + _from['name'])
    _from['anoncrypted_connection_response'] = to['anoncrypted_connection_response']

    print(tab + _from['name'] + ' -> Decrypt connection response from ' + to['name'])
    _from['connection_response'] = json.loads((await crypto.anon_decrypt(_from['wallet'],
                                                                         from_to_key,
                                                                         _from['anoncrypted_connection_response'])).decode("utf-8"))

    print(tab + _from['name'] + ' -> Compare nonce in response with original nonce for validation')
    assert _from['connection_request']['nonce'] == _from['connection_response']['nonce']

    print(tab + _from['name'] + ' -> Send pairwise did and key of ' + to['name'] + ' to ledger')
    await send_nym(_from['pool'], _from['wallet'], _from['did'], to_from_did, to_from_key, None)

    return from_to_did, from_to_key, to_from_did, to_from_key, _from['connection_response']


async def get_verinym(_from, to):

    print('====== Generate Verinym ======')

    name = to['name']
    from_to_key = _from['key_for_' + name]
    to_from_did = to['did_for_government']
    to_from_key = to['key_for_government']

    print(tab + to['name'] + ' -> Create did and key and store in wallet')
    (to_did, to_key) = await did.create_and_store_my_did(to['wallet'], "{}")

    print(tab + to['name'] + ' -> Create did info with the did and key')
    to['did_info'] = json.dumps({'did': to_did, 'verkey': to_key})

    print(tab + to['name'] + ' -> Encrypt the did info with pairwise key of ' + _from['name'])
    to['authcrypted_did_info'] = await crypto.auth_crypt(to['wallet'], to_from_key, from_to_key, to['did_info'].encode('utf-8'))

    print(tab + to['name'] + ' -> Send encrypted did info to ' + _from['name'])
    _from['authcrypted_did_info'] = to['authcrypted_did_info']

    print(tab + _from['name'] + ' -> Decrypt did info from ' + to['name'])
    sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info = await auth_decrypt(_from['wallet'],
                                                                                            from_to_key,
                                                                                            _from['authcrypted_did_info'])

    print(tab + _from['name'] + ' -> Compare pairwise key of ' + to['name'] + ' to validate')
    assert sender_verkey == await did.key_for_did(_from['pool'], _from['wallet'], to_from_did)

    print(tab + _from['name'] + ' -> Send did and key of ' + to['name'] + ' to ledger')
    await send_nym(_from['pool'], _from['wallet'], _from['did'], authdecrypted_did_info['did'], authdecrypted_did_info['verkey'], to['role'])

    return to_did


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)


async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, cred_def_request)


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
    return await ledger.parse_get_schema_response(get_schema_response)


async def get_cred_def(pool_handle, _did, cred_def_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, cred_def_id)
    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def auth_decrypt(wallet_handle, key, message):
    from_verkey, decrypted_message_json = await crypto.auth_decrypt(wallet_handle, key, message)
    decrypted_message_json = decrypted_message_json.decode("utf-8")
    decrypted_message = json.loads(decrypted_message_json)
    return from_verkey, decrypted_message_json, decrypted_message


if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run())
    time.sleep(1)
