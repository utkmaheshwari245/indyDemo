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
    print(tab + "Create Pool")
    try:
        await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    print(tab + "Get Pool Handle")
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print("Setup Government")
    government = {
        'name': "Government",
        'wallet_config': json.dumps({'id': 'government_wallet'}),
        'wallet_credentials': json.dumps({'key': 'government_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }
    print(tab + "Create Government Wallet")
    try:
        await wallet.create_wallet(government['wallet_config'], government['wallet_credentials'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass
    government['wallet'] = await wallet.open_wallet(government['wallet_config'], government['wallet_credentials'])
    government['did_info'] = json.dumps({'seed': government['seed']})
    print(tab + "Create DID and KEY and store in Wallet")
    government['did'], government['key'] = await did.create_and_store_my_did(government['wallet'], government['did_info'])

    print("==============================")
    print("==============================")

    print("Government -> Onboard SEC")
    sec = {
        'name': 'SEC',
        'wallet_config': json.dumps({'id': 'sec_wallet'}),
        'wallet_credentials': json.dumps({'key': 'sec_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    print(tab + "Government -> Establish p2p connection with SEC")
    government['did_for_sec'], government['key_for_sec'], sec['did_for_government'], sec['key_for_government'], _ = await onboarding(government, sec)
    print(tab + "Government -> Assign DID to SEC")
    sec['did'] = await get_verinym(government, sec, 'sec')

    print("Government -> Onboard Auditor")
    auditor = {
        'name': 'Auditor',
        'wallet_config': json.dumps({'id': 'auditor_wallet'}),
        'wallet_credentials': json.dumps({'key': 'auditor_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    print(tab + "Government -> Establish p2p connection with Auditor")
    government['did_for_auditor'], government['key_for_auditor'], auditor['did_for_government'], auditor['key_for_government'], _ = await onboarding(government, auditor)
    print(tab + "Government -> Assign DID to Auditor")
    auditor['did'] = await get_verinym(government, auditor, 'auditor')

    print("Government -> Onboard Goldman Sachs")
    goldman_sachs = {
        'name': 'Goldman Sachs',
        'wallet_config': json.dumps({'id': 'goldman_sachs_wallet'}),
        'wallet_credentials': json.dumps({'key': 'goldman_sachs_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    print(tab + "Government -> Establish p2p connection with Goldman Sachs")
    government['did_for_goldman_sachs'], government['key_for_goldman_sachs'], goldman_sachs['did_for_government'], goldman_sachs['key_for_government'], _ = await onboarding(government, goldman_sachs)
    print(tab + "Government -> Assign DID to Goldman Sachs")
    goldman_sachs['did'] = await get_verinym(government, goldman_sachs, 'goldman_sachs')

    print("==============================")

    print("SEC -> Create KYC Credential Schema")
    kyc = {
        'name': 'KYC',
        'version': '1.2',
        'attributes': ['name', 'id', 'rating']
    }
    (sec['kyc_schema_id'], sec['kyc_schema']) = await anoncreds.issuer_create_schema(sec['did'],
                                                                                     kyc['name'],
                                                                                     kyc['version'],
                                                                                     json.dumps(kyc['attributes']))
    kyc_schema_id = sec['kyc_schema_id']

    print("SEC -> Send KYC Credential Schema to Ledger")
    await send_schema(sec['pool'], sec['wallet'], sec['did'], sec['kyc_schema'])

    time.sleep(1) # sleep 1 second before getting schema

    print("==============================")

    print("Auditor -> Get KYC Schema from Ledger")
    (auditor['kyc_schema_id'], auditor['kyc_schema']) = await get_schema(auditor['pool'], auditor['did'], kyc_schema_id)

    print("Auditor -> Create and Store KYC Credential Definition in Wallet")
    kyc_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (auditor['kyc_cred_def_id'], auditor['kyc_cred_def']) = await anoncreds.issuer_create_and_store_credential_def(auditor['wallet'],
                                                                                                                   auditor['did'],
                                                                                                                   auditor['kyc_schema'],
                                                                                                                   kyc_cred_def['tag'],
                                                                                                                   kyc_cred_def['type'],
                                                                                                                   json.dumps(kyc_cred_def['config']))

    print("Auditor -> Send KYC Credential Definition to Ledger")
    await send_cred_def(auditor['pool'], auditor['wallet'], auditor['did'], auditor['kyc_cred_def'])

    print("==============================")

    print("Auditor -> Establish p2p connection with JP Morgan")
    jp_morgan = {
        'name': 'JP Morgan',
        'wallet_config': json.dumps({'id': 'jp_morgan_wallet'}),
        'wallet_credentials': json.dumps({'key': 'jp_morgan_wallet_key'}),
        'pool': pool_['handle'],
    }
    auditor['did_for_jp_morgan'], auditor['key_for_jp_morgan'], jp_morgan['did_for_auditor'], jp_morgan['key_for_auditor'], auditor['jp_morgan_connection_response'] = await onboarding(auditor, jp_morgan)

    print("Auditor -> Create KYC Credential Offer for JP Morgan")
    auditor['kyc_cred_offer'] = await anoncreds.issuer_create_credential_offer(auditor['wallet'], auditor['kyc_cred_def_id'])

    print("Auditor -> Encrypt KYC Credential Offer with JP Morgan\'s key")
    auditor['jp_morgan_key_for_auditor'] = await did.key_for_did(auditor['pool'], auditor['wallet'], auditor['jp_morgan_connection_response']['did'])
    auditor['authcrypted_kyc_cred_offer'] = await crypto.auth_crypt(auditor['wallet'],
                                                                    auditor['key_for_jp_morgan'],
                                                                    auditor['jp_morgan_key_for_auditor'],
                                                                    auditor['kyc_cred_offer'].encode('utf-8'))

    print("Auditor -> Send Encrypted KYC Credential Offer to JP Morgan")
    jp_morgan['authcrypted_kyc_cred_offer'] = auditor['authcrypted_kyc_cred_offer']

    print("==============================")

    print("JP Morgan -> Decrypt KYC Credential Offer from Auditor")
    jp_morgan['auditor_key_for_jp_morgan'], jp_morgan['kyc_cred_offer'], authdecrypted_kyc_cred_offer = await auth_decrypt(jp_morgan['wallet'],
                                                                                                                           jp_morgan['key_for_auditor'],
                                                                                                                           jp_morgan['authcrypted_kyc_cred_offer'])
    jp_morgan['kyc_schema_id'] = authdecrypted_kyc_cred_offer['schema_id']
    jp_morgan['kyc_cred_def_id'] = authdecrypted_kyc_cred_offer['cred_def_id']

    print("JP Morgan -> Create and Store Master Secret in Wallet")
    jp_morgan['master_secret_id'] = await anoncreds.prover_create_master_secret(jp_morgan['wallet'], None)

    print("JP Morgan -> Get KYC Credential Definition from Ledger")
    (jp_morgan['auditor_kyc_cred_def_id'], jp_morgan['auditor_kyc_cred_def']) = await get_cred_def(jp_morgan['pool'],
                                                                                                   jp_morgan['did_for_auditor'],
                                                                                                   authdecrypted_kyc_cred_offer['cred_def_id'])

    print("JP Morgan -> Create KYC Credential Request for Auditor")
    (jp_morgan['kyc_cred_request'], jp_morgan['kyc_cred_request_metadata']) = await anoncreds.prover_create_credential_req(jp_morgan['wallet'],
                                                                                                                           jp_morgan['did_for_auditor'],
                                                                                                                           jp_morgan['kyc_cred_offer'],
                                                                                                                           jp_morgan['auditor_kyc_cred_def'],
                                                                                                                           jp_morgan['master_secret_id'])

    print("JP Morgan -> Encrypt KYC Credential Request with Auditor\'s key")
    jp_morgan['authcrypted_kyc_cred_request'] = await crypto.auth_crypt(jp_morgan['wallet'],
                                                                        jp_morgan['key_for_auditor'],
                                                                        jp_morgan['auditor_key_for_jp_morgan'],
                                                                        jp_morgan['kyc_cred_request'].encode('utf-8'))

    print("JP Morgan -> Send encrypted KYC Credential Request to Auditor")
    auditor['authcrypted_kyc_cred_request'] = jp_morgan['authcrypted_kyc_cred_request']

    print("==============================")

    print("Auditor -> Decrypt KYC Credential Request from JP Morgan")
    auditor['jp_morgan_key_for_auditor'], auditor['kyc_cred_request'], _ = await auth_decrypt(auditor['wallet'],
                                                                                              auditor['key_for_jp_morgan'],
                                                                                              auditor['authcrypted_kyc_cred_request'])

    print("Auditor -> Create KYC Credential for JP Morgan")
    auditor['jp_morgan_kyc_cred_values'] = json.dumps({
        "name": {"raw": "JP Morgan", "encoded": "1139481716457488690172217916278103335"},
        "id": {"raw": "101", "encoded": "101"},
        "rating": {"raw": "5", "encoded": "5"}
    })
    auditor['kyc_cred'], _, _ = await anoncreds.issuer_create_credential(auditor['wallet'],
                                                                         auditor['kyc_cred_offer'],
                                                                         auditor['kyc_cred_request'],
                                                                         auditor['jp_morgan_kyc_cred_values'],
                                                                         None,
                                                                         None)

    print("Auditor -> Encrypt KYC Credential for JP Morgan")
    auditor['authcrypted_kyc_cred'] = await crypto.auth_crypt(auditor['wallet'],
                                                              auditor['key_for_jp_morgan'],
                                                              auditor['jp_morgan_key_for_auditor'],
                                                              auditor['kyc_cred'].encode('utf-8'))

    print("Auditor -> Send encrypted KYC Credential to JP Morgan")
    jp_morgan['authcrypted_kyc_cred'] = auditor['authcrypted_kyc_cred']

    print("==============================")

    print("JP Morgan -> Decrypt KYC Credential from auditor")
    _, jp_morgan['kyc_cred'], _ = await auth_decrypt(jp_morgan['wallet'],
                                                     jp_morgan['key_for_auditor'],
                                                     jp_morgan['authcrypted_kyc_cred'])

    print("JP Morgan -> Get KYC Credential Definition from Ledger")
    _, jp_morgan['kyc_cred_def'] = await get_cred_def(jp_morgan['pool'],
                                                      jp_morgan['did_for_auditor'],
                                                      jp_morgan['kyc_cred_def_id'])

    print("JP Morgan -> Store KYC Credential in Wallet")
    await anoncreds.prover_store_credential(jp_morgan['wallet'],
                                            None,
                                            jp_morgan['kyc_cred_request_metadata'],
                                            jp_morgan['kyc_cred'],
                                            jp_morgan['kyc_cred_def'],
                                            None)

    print("==============================")

    print("Goldman Sachs -> Establish p2p connection with JP Morgan")
    goldman_sachs['did_for_jp_morgan'], goldman_sachs['key_for_jp_morgan'], jp_morgan['did_for_goldman_sachs'], jp_morgan['key_for_goldman_sachs'], goldman_sachs['jp_morgan_connection_response'] = await onboarding(goldman_sachs, jp_morgan)

    print("Goldman Sachs -> Create KYC Credential Proof Request")
    nonce = await anoncreds.generate_nonce()
    goldman_sachs['kyc_cred_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'KYC Credential',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'name'
            },
            'attr2_referent': {
                'name': 'id',
                'restrictions': [{'cred_def_id': auditor['kyc_cred_def_id']}]
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'rating',
                'p_type': '>=',
                'p_value': 4,
                'restrictions': [{'cred_def_id': auditor['kyc_cred_def_id']}]
            }
        }
    })

    print("Goldman Sachs -> Encrypt KYC Credential Proof Request with JP Morgan\'s key")
    goldman_sachs['jp_morgan_key_for_goldman_sachs'] = await did.key_for_did(goldman_sachs['pool'],
                                                                             goldman_sachs['wallet'],
                                                                             goldman_sachs['jp_morgan_connection_response']['did'])
    goldman_sachs['authcrypted_kyc_cred_proof_request'] = await crypto.auth_crypt(goldman_sachs['wallet'],
                                                                                  goldman_sachs['key_for_jp_morgan'],
                                                                                  goldman_sachs['jp_morgan_key_for_goldman_sachs'],
                                                                                  goldman_sachs['kyc_cred_proof_request'].encode('utf-8'))

    print("Goldman Sachs -> Send encrypted KYC Credential Proof Request to JP Morgan")
    jp_morgan['authcrypted_kyc_cred_proof_request'] = goldman_sachs['authcrypted_kyc_cred_proof_request']

    print("==============================")

    print("JP Morgan -> Decrypt KYC Credential Proof Request from Goldman Sachs")
    jp_morgan['goldman_sachs_key_for_jp_morgan'], jp_morgan['kyc_cred_proof_request'], _ = await auth_decrypt(jp_morgan['wallet'],
                                                                                                              jp_morgan['key_for_goldman_sachs'],
                                                                                                              jp_morgan['authcrypted_kyc_cred_proof_request'])

    print("JP Morgan -> Get credentials for KYC Credential Proof Request")
    search_for_kyc_cred_proof_request = await anoncreds.prover_search_credentials_for_proof_req(jp_morgan['wallet'],
                                                                                                jp_morgan['kyc_cred_proof_request'],
                                                                                                None)
    cred_for_attr1 = await get_credential_for_referent(search_for_kyc_cred_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_kyc_cred_proof_request, 'attr2_referent')
    cred_for_predicate1 = await get_credential_for_referent(search_for_kyc_cred_proof_request, 'predicate1_referent')
    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_kyc_cred_proof_request)
    jp_morgan['creds_for_kyc_cred_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                             cred_for_attr2['referent']: cred_for_attr2,
                                             cred_for_predicate1['referent']: cred_for_predicate1}
    jp_morgan['schemas'], jp_morgan['cred_defs'], jp_morgan['revoc_states'] = await prover_get_entities_from_ledger(jp_morgan['pool'],
                                                                                                                    jp_morgan['did_for_goldman_sachs'],
                                                                                                                    jp_morgan['creds_for_kyc_cred_proof'])

    print("JP Morgan -> Create KYC Credential Proof")
    jp_morgan['kyc_cred_requested_creds'] = json.dumps({
        'self_attested_attributes': {'attr1_referent': 'JP Morgan'},
        'requested_attributes': {'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True}},
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })
    jp_morgan['kyc_cred_proof'] = await anoncreds.prover_create_proof(jp_morgan['wallet'],
                                                                      jp_morgan['kyc_cred_proof_request'],
                                                                      jp_morgan['kyc_cred_requested_creds'],
                                                                      jp_morgan['master_secret_id'],
                                                                      jp_morgan['schemas'],
                                                                      jp_morgan['cred_defs'],
                                                                      jp_morgan['revoc_states'])

    print("JP Morgan -> Encrypt KYC Credential Proof for Goldman Sachs")
    jp_morgan['authcrypted_kyc_cred_proof'] = await crypto.auth_crypt(jp_morgan['wallet'],
                                                                      jp_morgan['key_for_goldman_sachs'],
                                                                      jp_morgan['goldman_sachs_key_for_jp_morgan'],
                                                                      jp_morgan['kyc_cred_proof'].encode('utf-8'))

    print("JP Morgan -> Send encrypted KYC Credential Proof to Goldman Sachs")
    goldman_sachs['authcrypted_kyc_cred_proof'] = jp_morgan['authcrypted_kyc_cred_proof']

    print("==============================")

    print("Goldman Sachs -> Decrypt KYC Credential Proof from JP Morgan")
    _, goldman_sachs['kyc_cred_proof'], decrypted_kyc_cred_proof = await auth_decrypt(goldman_sachs['wallet'],
                                                                                      goldman_sachs['key_for_jp_morgan'],
                                                                                      goldman_sachs['authcrypted_kyc_cred_proof'])
    goldman_sachs['schemas'], goldman_sachs['cred_defs'], goldman_sachs['revoc_ref_defs'], goldman_sachs['revoc_regs'] = await verifier_get_entities_from_ledger(goldman_sachs['pool'],
                                                                                                                                                                 goldman_sachs['did'],
                                                                                                                                                                 decrypted_kyc_cred_proof['identifiers'])

    print("Goldman Sachs -> Verify KYC Credential Proof from JP Morgan")
    assert 'JP Morgan' == decrypted_kyc_cred_proof['requested_proof']['self_attested_attrs']['attr1_referent']
    assert '101' == decrypted_kyc_cred_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
    assert await anoncreds.verifier_verify_proof(goldman_sachs['kyc_cred_proof_request'],
                                                 goldman_sachs['kyc_cred_proof'],
                                                 goldman_sachs['schemas'],
                                                 goldman_sachs['cred_defs'],
                                                 goldman_sachs['revoc_ref_defs'],
                                                 goldman_sachs['revoc_regs'])

    print("==============================")
    print("==============================")

    print("Close and Delete Government\'s Wallet")
    await wallet.close_wallet(government['wallet'])
    await wallet.delete_wallet(government['wallet_config'], government['wallet_credentials'])

    print("Close and Delete SEC\'s Wallet")
    await wallet.close_wallet(sec['wallet'])
    await wallet.delete_wallet(sec['wallet_config'], sec['wallet_credentials'])

    print("Close and Delete Auditor\'s Wallet")
    await wallet.close_wallet(auditor['wallet'])
    await wallet.delete_wallet(auditor['wallet_config'], auditor['wallet_credentials'])

    print("Close and Delete Goldman Sachs\'s Wallet")
    await wallet.close_wallet(goldman_sachs['wallet'])
    await wallet.delete_wallet(goldman_sachs['wallet_config'], goldman_sachs['wallet_credentials'])

    print("Close and Delete JP Morgan\'s Wallet")
    await wallet.close_wallet(jp_morgan['wallet'])
    await wallet.delete_wallet(jp_morgan['wallet_config'], jp_morgan['wallet_credentials'])

    print("Close and Delete Pool")
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    print("============== Finish Demo ==============")


async def onboarding(_from, to):
    (from_to_did, from_to_key) = await did.create_and_store_my_did(_from['wallet'], "{}")
    await send_nym(_from['pool'], _from['wallet'], _from['did'], from_to_did, from_to_key, None)
    connection_request = {
        'did': from_to_did,
        'nonce': 123456789
    }

    if 'wallet' not in to:
        try:
            await wallet.create_wallet(to['wallet_config'], to['wallet_credentials'])
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass
        to['wallet'] = await wallet.open_wallet(to['wallet_config'], to['wallet_credentials'])

    (to_from_did, to_from_key) = await did.create_and_store_my_did(to['wallet'], "{}")
    from_to_verkey = await did.key_for_did(_from['pool'], to['wallet'], connection_request['did'])

    to['connection_response'] = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': connection_request['nonce']
    })
    to['anoncrypted_connection_response'] = await crypto.anon_crypt(from_to_verkey, to['connection_response'].encode('utf-8'))
    _from['anoncrypted_connection_response'] = to['anoncrypted_connection_response']
    _from['connection_response'] = json.loads((await crypto.anon_decrypt(_from['wallet'],
                                                                         from_to_key,
                                                                         _from['anoncrypted_connection_response'])).decode("utf-8"))

    assert connection_request['nonce'] == _from['connection_response']['nonce']
    await send_nym(_from['pool'], _from['wallet'], _from['did'], to_from_did, to_from_key, None)
    return from_to_did, from_to_key, to_from_did, to_from_key, _from['connection_response']


async def get_verinym(_from, to, name):
    from_to_key = _from['key_for_' + name]
    to_from_did = to['did_for_government']
    to_from_key = to['key_for_government']

    (to_did, to_key) = await did.create_and_store_my_did(to['wallet'], "{}")
    to['did_info'] = json.dumps({
        'did': to_did,
        'verkey': to_key
    })
    to['authcrypted_did_info'] = await crypto.auth_crypt(to['wallet'], to_from_key, from_to_key, to['did_info'].encode('utf-8'))

    sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info = await auth_decrypt(_from['wallet'],
                                                                                            from_to_key,
                                                                                            to['authcrypted_did_info'])

    assert sender_verkey == await did.key_for_did(_from['pool'], _from['wallet'], to_from_did)
    await send_nym(_from['pool'],
                   _from['wallet'],
                   _from['did'],
                   authdecrypted_did_info['did'],
                   authdecrypted_did_info['verkey'],
                   to['role'])

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
