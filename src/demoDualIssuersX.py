import asyncio
import time
import json

from indy import anoncreds, crypto, did, ledger, pool, wallet

tab = "    "

async def run():

    print("========================================")
    print("================ Set Up ================")
    print("========================================")

    print("Initialize Pool")
    await pool.set_protocol_version(2) # Set protocol version 2 to work with Indy Node 1.4
    pool_ = {
        'name': 'pool1',
        'config': json.dumps({"genesis_txn": '/home/indy/sandbox/pool_transactions_genesis'})
    }
    await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print("Initialize Government")
    gov = {
        'name': "gov",
        'wallet_config': json.dumps({'id': 'gov_wallet'}),
        'wallet_credentials': json.dumps({'key': 'gov_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }
    await wallet.create_wallet(gov['wallet_config'], gov['wallet_credentials'])
    gov['wallet'] = await wallet.open_wallet(gov['wallet_config'], gov['wallet_credentials'])
    gov['did_info'] = json.dumps({'seed': gov['seed']})
    (gov['did'], gov['key']) = await did.create_and_store_my_did(gov['wallet'], gov['did_info'])

    print('Initialize SEC')
    sec = {
        'name': 'sec',
        'wallet_config': json.dumps({'id': 'sec_wallet'}),
        'wallet_credentials': json.dumps({'key': 'sec_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    (gov['did_for_sec'], gov['key_for_sec'], sec['did_for_gov'], sec['key_for_gov'], _) = await onboarding(gov, sec)
    sec['did'] = await get_verinym(gov, sec)

    print('Initialize Goldman Sachs')
    gs = {
        'name': 'gs',
        'wallet_config': json.dumps({'id': 'gs_wallet'}),
        'wallet_credentials': json.dumps({'key': 'gs_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    (gov['did_for_gs'], gov['key_for_gs'], gs['did_for_gov'], gs['key_for_gov'], _) = await onboarding(gov, gs)
    gs['did'] = await get_verinym(gov, gs)

    print('Initialize JP Morgan')
    jp = {
        'name': 'jp',
        'wallet_config': json.dumps({'id': 'jp_wallet'}),
        'wallet_credentials': json.dumps({'key': 'jp_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    (gov['did_for_jp'], gov['key_for_jp'], jp['did_for_gov'], jp['key_for_gov'], _) = await onboarding(gov, jp)
    jp['did'] = await get_verinym(gov, jp)

    print('Initialize Two Sigma')
    sig = {
        'name': 'sig',
        'wallet_config': json.dumps({'id': 'sig_wallet'}),
        'wallet_credentials': json.dumps({'key': 'sig_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    (gov['did_for_sig'], gov['key_for_sig'], sig['did_for_gov'], sig['key_for_gov'], _) = await onboarding(gov, sig)
    sig['did'] = await get_verinym(gov, sig)

    print("========================================")
    print("============== Start Demo ==============")
    print("========================================")

    print("SEC -> Create KYC Credential Schema")
    kyc = {
        'name': 'KYC',
        'version': '1.2',
        'attributes': ['id', 'legalName', 'legalOwner', 'primarySicCode', 'address']
    }
    (sec['kyc_schema_id'], sec['kyc_schema']) = await anoncreds.issuer_create_schema(sec['did'], kyc['name'], kyc['version'], json.dumps(kyc['attributes']))
    kyc_schema_id = sec['kyc_schema_id']

    print("SEC -> Send KYC Credential Schema to Ledger")
    await send_schema(sec['pool'], sec['wallet'], sec['did'], sec['kyc_schema'])

    time.sleep(1) # sleep 1 second before getting schema

    print("========================================")

    print("Goldman Sachs -> Get KYC Schema from Ledger")
    (gs['kyc_schema_id'], gs['kyc_schema']) = await get_schema(gs['pool'], gs['did'], kyc_schema_id)

    print("Goldman Sachs -> Create and Store KYC Credential Definition in Wallet")
    kyc_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (gs['kyc_cred_def_id'], gs['kyc_cred_def']) = await anoncreds.issuer_create_and_store_credential_def(gs['wallet'], gs['did'], gs['kyc_schema'], kyc_cred_def['tag'],
                                                                                                         kyc_cred_def['type'], json.dumps(kyc_cred_def['config']))

    print("Goldman Sachs -> Send KYC Credential Definition to Ledger")
    await send_cred_def(gs['pool'], gs['wallet'], gs['did'], gs['kyc_cred_def'])

    print("Goldman Sachs -> Establish p2p connection with Two Sigma")
    (gs['did_for_sig'], gs['key_for_sig'], sig['did_for_gs'], sig['key_for_gs'], gs['sig_connection_response']) = await onboarding(gs, sig)

    print("Goldman Sachs -> Create KYC Credential Offer for Two Sigma")
    gs['kyc_cred_offer'] = await anoncreds.issuer_create_credential_offer(gs['wallet'], gs['kyc_cred_def_id'])

    print("Goldman Sachs -> Encrypt KYC Credential Offer with Two Sigma\'s key")
    gs['sig_key_for_gs'] = await did.key_for_did(gs['pool'], gs['wallet'], gs['sig_connection_response']['did'])
    gs['authcrypted_kyc_cred_offer'] = await crypto.auth_crypt(gs['wallet'], gs['key_for_sig'], gs['sig_key_for_gs'], gs['kyc_cred_offer'].encode('utf-8'))

    print("Goldman Sachs -> Send Encrypted KYC Credential Offer to Two Sigma")
    sig['authcrypted_kyc_cred_offer'] = gs['authcrypted_kyc_cred_offer']

    print("========================================")

    print("Two Sigma -> Create and Store Master Secret in Wallet")
    sig['master_secret_id'] = await anoncreds.prover_create_master_secret(sig['wallet'], None)

    print("Two Sigma -> Decrypt KYC Credential Offer from Goldman Sachs")
    (sig['gs_key_for_sig'], sig['kyc_cred_offer'], authdecrypted_kyc_cred_offer) = await auth_decrypt(sig['wallet'], sig['key_for_gs'], sig['authcrypted_kyc_cred_offer'])
    sig['kyc_schema_id'] = authdecrypted_kyc_cred_offer['schema_id']
    sig['kyc_cred_def_id'] = authdecrypted_kyc_cred_offer['cred_def_id']

    print("Two Sigma -> Get KYC Credential Definition from Ledger")
    (sig['gs_kyc_cred_def_id'], sig['gs_kyc_cred_def']) = await get_cred_def(sig['pool'], sig['did_for_gs'], authdecrypted_kyc_cred_offer['cred_def_id'])

    print("Two Sigma -> Create KYC Credential Request for Goldman Sachs")
    (sig['kyc_cred_request'], sig['kyc_cred_request_metadata']) = await anoncreds.prover_create_credential_req(sig['wallet'], sig['did_for_gs'], sig['kyc_cred_offer'],
                                                                                                               sig['gs_kyc_cred_def'], sig['master_secret_id'])

    print("Two Sigma -> Encrypt KYC Credential Request with Goldman Sachs\'s key")
    sig['authcrypted_kyc_cred_request'] = await crypto.auth_crypt(sig['wallet'], sig['key_for_gs'], sig['gs_key_for_sig'], sig['kyc_cred_request'].encode('utf-8'))

    print("Two Sigma -> Send encrypted KYC Credential Request to Goldman Sachs")
    gs['authcrypted_kyc_cred_request'] = sig['authcrypted_kyc_cred_request']

    print("========================================")

    print("Goldman Sachs -> Decrypt KYC Credential Request from Two Sigma")
    (gs['sig_key_for_gs'], gs['kyc_cred_request'], _) = await auth_decrypt(gs['wallet'], gs['key_for_sig'], gs['authcrypted_kyc_cred_request'])

    print("Goldman Sachs -> Create KYC Credential for Two Sigma")
    gs['sig_kyc_cred_values'] = json.dumps({
        "id": {"raw": "101", "encoded": "101"},
        "legalName": {"raw": "Two Sigma Coop.", "encoded": "00010203040506070809"},
        "legalOwner": {"raw": "Mr. Morgan", "encoded": "10111213141516171819"},
        "primarySicCode": {"raw": "1102", "encoded": "1102"},
        "address": {"raw": "207A, Mulberry Woods, New York", "encoded": "20212223242526272829"}
    })
    (gs['kyc_cred'], _, _) = await anoncreds.issuer_create_credential(gs['wallet'], gs['kyc_cred_offer'], gs['kyc_cred_request'], gs['sig_kyc_cred_values'], None, None)

    print("Goldman Sachs -> Encrypt KYC Credential for Two Sigma")
    gs['authcrypted_kyc_cred'] = await crypto.auth_crypt(gs['wallet'], gs['key_for_sig'], gs['sig_key_for_gs'], gs['kyc_cred'].encode('utf-8'))

    print("Goldman Sachs -> Send encrypted KYC Credential to Two Sigma")
    sig['authcrypted_kyc_cred'] = gs['authcrypted_kyc_cred']

    print("========================================")

    print("Two Sigma -> Decrypt KYC Credential from Goldman Sachs")
    (_, sig['kyc_cred'], _) = await auth_decrypt(sig['wallet'], sig['key_for_gs'], sig['authcrypted_kyc_cred'])

    print("Two Sigma -> Get KYC Credential Definition from Ledger")
    (_, sig['kyc_cred_def']) = await get_cred_def(sig['pool'], sig['did_for_gs'], sig['kyc_cred_def_id'])

    print("Two Sigma -> Store KYC Credential in Wallet")
    await anoncreds.prover_store_credential(sig['wallet'], None, sig['kyc_cred_request_metadata'], sig['kyc_cred'], sig['kyc_cred_def'], None)

    print("========================================")

    print("JP Morgan -> Establish p2p connection with Two Sigma")
    (jp['did_for_sig'], jp['key_for_sig'], sig['did_for_jp'], sig['key_for_jp'], jp['sig_connection_response']) = await onboarding(jp, sig)

    print("JP Morgan -> Get Two Sigma\'s key")
    jp['sig_key_for_jp'] = await did.key_for_did(jp['pool'], jp['wallet'], jp['sig_connection_response']['did'])

    print("JP Morgan -> Create KYC Credential Proof Request")
    nonce1 = await anoncreds.generate_nonce()
    jp['kyc_cred_proof_request'] = json.dumps({
        'nonce': nonce1,
        'name': 'KYC Credential',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'id',
                'restrictions': [{'cred_def_id': gs['kyc_cred_def_id']}]
            },
            'attr2_referent': {
                'name': 'legalName',
                'restrictions': [{'cred_def_id': gs['kyc_cred_def_id']}]
            },
            'attr3_referent': {
                'name': 'legalOwner',
                'restrictions': [{'cred_def_id': gs['kyc_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'primarySicCode',
                'restrictions': [{'cred_def_id': gs['kyc_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'address',
                'restrictions': [{'cred_def_id': gs['kyc_cred_def_id']}]
            }
        },
        'requested_predicates': {}
    })

    print("JP Morgan -> Encrypt KYC Credential Proof Request with Two Sigma\'s key")
    jp['authcrypted_kyc_cred_proof_request'] = await crypto.auth_crypt(jp['wallet'], jp['key_for_sig'], jp['sig_key_for_jp'], jp['kyc_cred_proof_request'].encode('utf-8'))

    print("JP Morgan -> Send encrypted KYC Credential Proof Request to Two Sigma")
    sig['authcrypted_kyc_cred_proof_request'] = jp['authcrypted_kyc_cred_proof_request']

    print("========================================")

    print("Two Sigma -> Decrypt KYC Credential Proof Request from JP Morgan")
    (sig['jp_key_for_sig'], sig['kyc_cred_proof_request'], _) = await auth_decrypt(sig['wallet'], sig['key_for_jp'], sig['authcrypted_kyc_cred_proof_request'])

    print("Two Sigma -> Get credentials for KYC Credential Proof Request")
    search_for_kyc_cred_proof_request = await anoncreds.prover_search_credentials_for_proof_req(sig['wallet'], sig['kyc_cred_proof_request'], None)
    cred_for_attr1 = await get_credential_for_referent(search_for_kyc_cred_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_kyc_cred_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_kyc_cred_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_kyc_cred_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_kyc_cred_proof_request, 'attr5_referent')
    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_kyc_cred_proof_request)
    sig['creds_for_kyc_cred_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                       cred_for_attr2['referent']: cred_for_attr2,
                                       cred_for_attr3['referent']: cred_for_attr3,
                                       cred_for_attr4['referent']: cred_for_attr4,
                                       cred_for_attr5['referent']: cred_for_attr5}
    (sig['kyc_schemas'], sig['kyc_cred_defs'], sig['kyc_revoc_states']) = await prover_get_entities_from_ledger(sig['pool'], sig['did_for_jp'], sig['creds_for_kyc_cred_proof'])

    print("Two Sigma -> Create KYC Credential Proof")
    sig['kyc_cred_requested_creds'] = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
                                 'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
                                 'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
                                 'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
                                 'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True}},
        'requested_predicates': {}
    })
    sig['kyc_cred_proof'] = await anoncreds.prover_create_proof(sig['wallet'], sig['kyc_cred_proof_request'], sig['kyc_cred_requested_creds'],
                                                                sig['master_secret_id'], sig['kyc_schemas'], sig['kyc_cred_defs'], sig['kyc_revoc_states'])

    print("Two Sigma -> Encrypt KYC Credential Proof for JP Morgan")
    sig['authcrypted_kyc_cred_proof'] = await crypto.auth_crypt(sig['wallet'], sig['key_for_jp'], sig['jp_key_for_sig'], sig['kyc_cred_proof'].encode('utf-8'))

    print("Two Sigma -> Send encrypted KYC Credential Proof to JP Morgan")
    jp['authcrypted_kyc_cred_proof'] = sig['authcrypted_kyc_cred_proof']

    print("========================================")

    print("JP Morgan -> Decrypt KYC Credential Proof from Two Sigma")
    (_, jp['kyc_cred_proof'], decrypted_kyc_cred_proof) = await auth_decrypt(jp['wallet'], jp['key_for_sig'], jp['authcrypted_kyc_cred_proof'])
    (jp['kyc_schemas'], jp['kyc_cred_defs'], jp['kyc_revoc_ref_defs'], jp['kyc_revoc_regs']) = await verifier_get_entities_from_ledger(jp['pool'], jp['did'],
                                                                                                                                       decrypted_kyc_cred_proof['identifiers'])

    print("JP Morgan -> Verify KYC Credential Proof from Two Sigma")
    assert '101' == decrypted_kyc_cred_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
    assert 'Two Sigma Coop.' == decrypted_kyc_cred_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
    assert 'Mr. Morgan' == decrypted_kyc_cred_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert '1102' == decrypted_kyc_cred_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '207A, Mulberry Woods, New York' == decrypted_kyc_cred_proof['requested_proof']['revealed_attrs']['attr5_referent']['raw']
    assert await anoncreds.verifier_verify_proof(jp['kyc_cred_proof_request'], jp['kyc_cred_proof'], jp['kyc_schemas'],
                                                 jp['kyc_cred_defs'], jp['kyc_revoc_ref_defs'], jp['kyc_revoc_regs'])

    print("========================================")

    print("Close and Delete gov\'s Wallet")
    await wallet.close_wallet(gov['wallet'])
    await wallet.delete_wallet(gov['wallet_config'], gov['wallet_credentials'])

    print("Close and Delete SEC\'s Wallet")
    await wallet.close_wallet(sec['wallet'])
    await wallet.delete_wallet(sec['wallet_config'], sec['wallet_credentials'])

    print("Close and Delete Goldman Sachs\'s Wallet")
    await wallet.close_wallet(gs['wallet'])
    await wallet.delete_wallet(gs['wallet_config'], gs['wallet_credentials'])

    print("Close and Delete JP Morgan\'s Wallet")
    await wallet.close_wallet(jp['wallet'])
    await wallet.delete_wallet(jp['wallet_config'], jp['wallet_credentials'])

    print("Close and Delete Two Sigma\'s Wallet")
    await wallet.close_wallet(sig['wallet'])
    await wallet.delete_wallet(sig['wallet_config'], sig['wallet_credentials'])

    print("Close and Delete Pool")
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    print("========================================")
    print("=============== End Demo ===============")
    print("========================================")


async def onboarding(_from, _to):

    (from_to_did, from_to_key) = await did.create_and_store_my_did(_from['wallet'], "{}")
    await send_nym(_from['pool'], _from['wallet'], _from['did'], from_to_did, from_to_key, None)
    _from['connection_request'] = {'did': from_to_did, 'nonce': 123456789}
    _to['connection_request'] = _from['connection_request']

    if 'wallet' not in _to:
        await wallet.create_wallet(_to['wallet_config'], _to['wallet_credentials'])
        _to['wallet'] = await wallet.open_wallet(_to['wallet_config'], _to['wallet_credentials'])
    (to_from_did, to_from_key) = await did.create_and_store_my_did(_to['wallet'], "{}")
    _to['connection_response'] = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': _to['connection_request']['nonce']
    })
    from_to_verkey = await did.key_for_did(_from['pool'], _to['wallet'], _to['connection_request']['did'])
    _to['anoncrypted_connection_response'] = await crypto.anon_crypt(from_to_verkey, _to['connection_response'].encode('utf-8'))
    _from['anoncrypted_connection_response'] = _to['anoncrypted_connection_response']

    _from['connection_response'] = json.loads((await crypto.anon_decrypt(_from['wallet'], from_to_key, _from['anoncrypted_connection_response'])).decode("utf-8"))
    assert _from['connection_request']['nonce'] == _from['connection_response']['nonce']
    await send_nym(_from['pool'], _from['wallet'], _from['did'], to_from_did, to_from_key, None)

    return (from_to_did, from_to_key, to_from_did, to_from_key, _from['connection_response'])


async def get_verinym(_from, _to):

    name = _to['name']
    from_to_key = _from['key_for_' + name]
    to_from_did = _to['did_for_gov']
    to_from_key = _to['key_for_gov']

    (to_did, to_key) = await did.create_and_store_my_did(_to['wallet'], "{}")
    _to['did_info'] = json.dumps({'did': to_did, 'verkey': to_key})
    _to['authcrypted_did_info'] = await crypto.auth_crypt(_to['wallet'], to_from_key, from_to_key, _to['did_info'].encode('utf-8'))
    _from['authcrypted_did_info'] = _to['authcrypted_did_info']

    (sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info) = await auth_decrypt(_from['wallet'], from_to_key, _from['authcrypted_did_info'])
    assert sender_verkey == await did.key_for_did(_from['pool'], _from['wallet'], to_from_did)
    await send_nym(_from['pool'], _from['wallet'], _from['did'], authdecrypted_did_info['did'], authdecrypted_did_info['verkey'], _to['role'])

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
