import asyncio
import time
import json


from indy import anoncreds, crypto, did, ledger, pool, wallet, blob_storage
from os.path import dirname


async def run():
    print("========================================")
    print("============== Start Demo ==============")
    print("========================================")
    input("")
    (pool_, gov, gs, jp, sig) = await system___set_up()
    input("")
    await gov___create_cred_schema__post_cred_schema_to_ledger__send_cred_schema_id_to_gs(gov, gs)
    input("")
    await gs___get_cred_schema_from_ledger__create_cred_definition__post_cred_definition_to_ledger__send_cred_definition_id_to_jp(gs, jp)
    input("")
    await gs___create_revocation_registry__post_revocation_registry_definition_to_ledger__post_revocation_registry_entry_to_ledger(gs)
    input("")
    await gs___establish_connection_with_sig__create_cred_offer__encrypt_cred_offer__send_cred_offer_to_sig(gs, sig)
    input("")
    await sig___decrypt_cred_offer_from_gs__create_cred_request__encrypt_cred_request__send_cred_request_to_gs(sig, gs)
    input("")
    await gs___decrypt_cred_request_from_sig__create_cred__encrypt_cred__send_cred_to_sig__post_revocation_registry_delta_to_ledger(gs, sig)
    input("")
    await sig___decrypt_cred_from_gs__store_cred_in_wallet(sig)
    input("")
    await jp___establish_connection_with_sig__create_cred_proof_request__encrypt_cred_proof_request__send_cred_request_to_sig(jp, sig)
    input("")
    await sig___decrypt_cred_proof_request_from_jp__create_cred_proof__encrypt_cred_proof__send_cred_proof_to_jp(sig, jp)
    input("")
    await jp___decrypt_cred_proof_from_sig__verify_cred_proof(jp, False)
    input("")
    await gs___revoke_cred_for_sig__post_revocation_registry_delta_to_ledger(gs)
    input("")
    await jp___establish_connection_with_sig__create_cred_proof_request__encrypt_cred_proof_request__send_cred_request_to_sig(jp, sig)
    input("")
    await sig___decrypt_cred_proof_request_from_jp__create_cred_proof__encrypt_cred_proof__send_cred_proof_to_jp(sig, jp)
    input("")
    await jp___decrypt_cred_proof_from_sig__verify_cred_proof(jp, True)
    input("")
    await system___tear_down(pool_, gov, gs, jp, sig)
    input("")
    print("========================================")
    print("=============== End Demo ===============")
    print("========================================")


async def system___set_up():
    print("Initialize Pool (Blockchain Ledger)")
    await pool.set_protocol_version(2)
    pool_ = {
        'name': 'pool1',
        'config': json.dumps({"genesis_txn": '/home/indy/sandbox/pool_transactions_genesis'})
    }
    await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print("Initialize Government (Blockchain Steward)")
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

    print("Initialize Goldman Sachs (KYC Credential Issuer)")
    gs = {
        'name': 'gs',
        'wallet_config': json.dumps({'id': 'gs_wallet'}),
        'wallet_credentials': json.dumps({'key': 'gs_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    (gov['did_for_gs'], gov['key_for_gs'], gs['did_for_gov'], gs['key_for_gov'], _) = await get_pseudonym(gov, gs)
    gs['did'] = await get_verinym(gov, gs)

    print("Initialize JP Morgan (KYC Credential Verifier)")
    jp = {
        'name': 'jp',
        'wallet_config': json.dumps({'id': 'jp_wallet'}),
        'wallet_credentials': json.dumps({'key': 'jp_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    (gov['did_for_jp'], gov['key_for_jp'], jp['did_for_gov'], jp['key_for_gov'], _) = await get_pseudonym(gov, jp)
    jp['did'] = await get_verinym(gov, jp)

    print("Initialize Two Sigma (KYC Credential Holder)")
    sig = {
        'name': 'sig',
        'wallet_config': json.dumps({'id': 'sig_wallet'}),
        'wallet_credentials': json.dumps({'key': 'sig_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    (gov['did_for_sig'], gov['key_for_sig'], sig['did_for_gov'], sig['key_for_gov'], _) = await get_pseudonym(gov, sig)
    sig['did'] = await get_verinym(gov, sig)

    print("========================================")

    return (pool_, gov, gs, jp, sig)


async def gov___create_cred_schema__post_cred_schema_to_ledger__send_cred_schema_id_to_gs(gov, gs):
    print("Government -> Create KYC Credential Schema : ['legalName', 'primarySicCode', 'address', 'liquidity', 'rating']")
    cred_schema = {
        'name': 'KYC',
        'version': '1.2',
        'attributes': ['legalName', 'primarySicCode', 'address', 'liquidity', 'rating']
    }
    (gov['cred_schema_id'], gov['cred_schema']) = await anoncreds.issuer_create_schema(gov['did'], cred_schema['name'], cred_schema['version'], json.dumps(cred_schema['attributes']))

    print("Government -> Post KYC Credential Schema to Ledger")
    await send_schema(gov['pool'], gov['wallet'], gov['did'], gov['cred_schema'])

    print("Government -> Send KYC Credential Schema Id to Goldman Sachs")
    gs['cred_schema_id'] = gov['cred_schema_id']

    print("========================================")


async def gs___get_cred_schema_from_ledger__create_cred_definition__post_cred_definition_to_ledger__send_cred_definition_id_to_jp(gs, jp):
    print("Goldman Sachs -> Get KYC Schema from Ledger")
    (_, gs['cred_schema']) = await get_schema(gs['pool'], gs['did'], gs['cred_schema_id'])

    print("Goldman Sachs -> Create KYC Credential Definition")
    cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": True}
    }
    (gs['cred_def_id'], gs['cred_def']) = await anoncreds.issuer_create_and_store_credential_def(gs['wallet'], gs['did'], gs['cred_schema'], cred_def['tag'],
                                                                                                 cred_def['type'], json.dumps(cred_def['config']))

    print("Goldman Sachs -> Post KYC Credential Definition to Ledger")
    await send_cred_def(gs['pool'], gs['wallet'], gs['did'], gs['cred_def'])

    print("Goldman Sachs -> Send KYC Credential Definition Id to JP Morgan")
    jp['cred_def_id'] = gs['cred_def_id']

    print("----------------------------------------")


async def gs___create_revocation_registry__post_revocation_registry_definition_to_ledger__post_revocation_registry_entry_to_ledger(gs):
    print("Goldman Sachs -> Create Revocation Registry")
    gs['tails_writer_config'] = json.dumps({'base_dir': "/tmp/indy_acme_tails", 'uri_pattern': ''})
    tails_writer = await blob_storage.open_writer('default', gs['tails_writer_config'])
    (gs['cred_revoc_reg_id'], gs['cred_revoc_reg_def'], gs['cred_revoc_reg_entry']) = await anoncreds.issuer_create_and_store_revoc_reg(gs['wallet'], gs['did'], 'CL_ACCUM', 'TAG1',
                                                                                                                                        gs['cred_def_id'], '{}', tails_writer)

    print("Goldman Sachs -> Post Revocation Registry Definition to Ledger")
    await send_revoc_reg_def(gs['pool'], gs['wallet'], gs['did'], gs['cred_revoc_reg_def'])

    print("Goldman Sachs -> Post Revocation Registry Entry to Ledger")
    await send_revoc_reg_entry_or_delta(gs['pool'], gs['wallet'], gs['did'], gs['cred_revoc_reg_id'], gs['cred_revoc_reg_entry'])

    print("----------------------------------------")

async def gs___establish_connection_with_sig__create_cred_offer__encrypt_cred_offer__send_cred_offer_to_sig(gs, sig):
    print("Goldman Sachs -> Establish p2p connection with Two Sigma")
    (gs['did_for_sig'], gs['key_for_sig'], sig['did_for_gs'], sig['key_for_gs'], gs['sig_connection_response']) = await get_pseudonym(gs, sig)

    print("Goldman Sachs -> Create KYC Credential Offer")
    gs['cred_offer'] = await anoncreds.issuer_create_credential_offer(gs['wallet'], gs['cred_def_id'])

    print("Goldman Sachs -> Encrypt KYC Credential Offer")
    gs['sig_key_for_gs'] = await did.key_for_did(gs['pool'], gs['wallet'], gs['sig_connection_response']['did'])
    gs['authcrypted_cred_offer'] = await crypto.auth_crypt(gs['wallet'], gs['key_for_sig'], gs['sig_key_for_gs'], gs['cred_offer'].encode('utf-8'))

    print("Goldman Sachs -> Send Encrypted KYC Credential Offer to Two Sigma")
    sig['authcrypted_cred_offer'] = gs['authcrypted_cred_offer']

    print("========================================")


async def sig___decrypt_cred_offer_from_gs__create_cred_request__encrypt_cred_request__send_cred_request_to_gs(sig, gs):
    print("Two Sigma -> Decrypt KYC Credential Offer from Goldman Sachs")
    (sig['gs_key_for_sig'], sig['cred_offer'], authdecrypted_cred_offer) = await auth_decrypt(sig['wallet'], sig['key_for_gs'], sig['authcrypted_cred_offer'])
    sig['cred_schema_id'] = authdecrypted_cred_offer['schema_id']
    sig['cred_def_id'] = authdecrypted_cred_offer['cred_def_id']

    print("Two Sigma -> Create KYC Credential Request")
    sig['master_secret_id'] = await anoncreds.prover_create_master_secret(sig['wallet'], None)
    (sig['gs_cred_def_id'], sig['gs_cred_def']) = await get_cred_def(sig['pool'], sig['did'], authdecrypted_cred_offer['cred_def_id'])
    (sig['cred_request'], sig['cred_request_metadata']) = await anoncreds.prover_create_credential_req(sig['wallet'], sig['did'], sig['cred_offer'],
                                                                                                       sig['gs_cred_def'], sig['master_secret_id'])

    print("Two Sigma -> Encrypt KYC Credential Request")
    sig['authcrypted_cred_request'] = await crypto.auth_crypt(sig['wallet'], sig['key_for_gs'], sig['gs_key_for_sig'], sig['cred_request'].encode('utf-8'))

    print("Two Sigma -> Send encrypted KYC Credential Request to Goldman Sachs")
    gs['authcrypted_cred_request'] = sig['authcrypted_cred_request']

    print("========================================")


async def gs___decrypt_cred_request_from_sig__create_cred__encrypt_cred__send_cred_to_sig__post_revocation_registry_delta_to_ledger(gs, sig):
    print("Goldman Sachs -> Decrypt KYC Credential Request from Two Sigma")
    (gs['sig_key_for_gs'], gs['cred_request'], _) = await auth_decrypt(gs['wallet'], gs['key_for_sig'], gs['authcrypted_cred_request'])

    print("Goldman Sachs -> Create KYC Credential")
    gs['sig_cred_values'] = json.dumps({
        "legalName": {"raw": "Two Sigma Coop.", "encoded": "00010203040506070809"},
        "primarySicCode": {"raw": "1102", "encoded": "1102"},
        "address": {"raw": "207A, Mulberry Woods, New York", "encoded": "20212223242526272829"},
        "liquidity": {"raw": "2.8", "encoded": "2.8"},
        "rating": {"raw": "4", "encoded": "4"}
    })
    gs['blob_storage_reader_cfg_handle'] = await blob_storage.open_reader('default', gs['tails_writer_config'])
    (gs['cred'], gs['cred_rev_id'], gs['cred_rev_reg_delta']) = await anoncreds.issuer_create_credential(gs['wallet'], gs['cred_offer'], gs['cred_request'], gs['sig_cred_values'],
                                                                                                         gs['cred_revoc_reg_id'], gs['blob_storage_reader_cfg_handle'])

    print("Goldman Sachs -> Encrypt KYC Credential")
    gs['authcrypted_cred'] = await crypto.auth_crypt(gs['wallet'], gs['key_for_sig'], gs['sig_key_for_gs'], gs['cred'].encode('utf-8'))

    print("Goldman Sachs -> Send encrypted KYC Credential to Two Sigma")
    sig['authcrypted_cred'] = gs['authcrypted_cred']

    print("Goldman Sachs -> Post Revocation Registry Delta to Ledger")
    await send_revoc_reg_entry_or_delta(gs['pool'], gs['wallet'], gs['did'], gs['cred_revoc_reg_id'], gs['cred_rev_reg_delta'])

    print("========================================")


async def sig___decrypt_cred_from_gs__store_cred_in_wallet(sig):
    print("Two Sigma -> Decrypt KYC Credential from Goldman Sachs")
    (_, sig['cred'], cred) = await auth_decrypt(sig['wallet'], sig['key_for_gs'], sig['authcrypted_cred'])

    print("Two Sigma -> Store KYC Credential in Wallet")
    (_, sig['cred_def']) = await get_cred_def(sig['pool'], sig['did'], sig['cred_def_id'])
    (_, sig['revoc_reg_def_json']) = await get_revoc_reg_def(sig['pool'], sig['did'], cred['rev_reg_id'])
    await anoncreds.prover_store_credential(sig['wallet'], None, sig['cred_request_metadata'], sig['cred'], sig['cred_def'], sig['revoc_reg_def_json'])

    print("========================================")


async def jp___establish_connection_with_sig__create_cred_proof_request__encrypt_cred_proof_request__send_cred_request_to_sig(jp, sig):
    print("JP Morgan -> Establish p2p connection with Two Sigma")
    (jp['did_for_sig'], jp['key_for_sig'], sig['did_for_jp'], sig['key_for_jp'], jp['sig_connection_response']) = await get_pseudonym(jp, sig)

    print("JP Morgan -> Create KYC Credential Proof Request")
    nonce1 = await anoncreds.generate_nonce()
    jp['cred_proof_request'] = json.dumps({
        'nonce': nonce1,
        'name': 'KYC Credential',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'legalName',
                'restrictions': [{'cred_def_id': jp['cred_def_id']}]
            },
            'attr2_referent': {
                'name': 'primarySicCode',
                'restrictions': [{'cred_def_id': jp['cred_def_id']}]
            },
            'attr3_referent': {
                'name': 'address',
                'restrictions': [{'cred_def_id': jp['cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'liquidity',
                'restrictions': [{'cred_def_id': jp['cred_def_id']}]
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'rating',
                'p_type': '>=',
                'p_value': 3,
                'restrictions': [{'cred_def_id': jp['cred_def_id']}]
            }
        },
        'non_revoked': {'to': int(time.time())}
    })

    print("JP Morgan -> Encrypt KYC Credential Proof Request")
    jp['sig_key_for_jp'] = await did.key_for_did(jp['pool'], jp['wallet'], jp['sig_connection_response']['did'])
    jp['authcrypted_cred_proof_request'] = await crypto.auth_crypt(jp['wallet'], jp['key_for_sig'], jp['sig_key_for_jp'], jp['cred_proof_request'].encode('utf-8'))

    print("JP Morgan -> Send encrypted KYC Credential Proof Request to Two Sigma")
    sig['authcrypted_cred_proof_request'] = jp['authcrypted_cred_proof_request']

    print("========================================")


async def sig___decrypt_cred_proof_request_from_jp__create_cred_proof__encrypt_cred_proof__send_cred_proof_to_jp(sig, jp):
    print("Two Sigma -> Decrypt KYC Credential Proof Request from JP Morgan")
    (sig['jp_key_for_sig'], sig['cred_proof_request'], _) = await auth_decrypt(sig['wallet'], sig['key_for_jp'], sig['authcrypted_cred_proof_request'])

    print("Two Sigma -> Get credentials for KYC Credential Proof Request")
    requested_credentials = json.loads(await anoncreds.prover_get_credentials_for_proof_req(sig['wallet'], sig['cred_proof_request']))
    cred_for_attr1 = requested_credentials['attrs']['attr1_referent'][0]['cred_info']
    cred_for_attr2 = requested_credentials['attrs']['attr2_referent'][0]['cred_info']
    cred_for_attr3 = requested_credentials['attrs']['attr3_referent'][0]['cred_info']
    cred_for_attr4 = requested_credentials['attrs']['attr4_referent'][0]['cred_info']
    cred_for_predicate1 = requested_credentials['predicates']['predicate1_referent'][0]['cred_info']
    sig['creds_for_cred_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                   cred_for_attr2['referent']: cred_for_attr2,
                                   cred_for_attr3['referent']: cred_for_attr3,
                                   cred_for_attr4['referent']: cred_for_attr4,
                                   cred_for_predicate1['referent']: cred_for_predicate1}
    requested_timestamp = int(json.loads(sig['cred_proof_request'])['non_revoked']['to'])
    (sig['cred_schemas'], sig['cred_defs'], sig['cred_revoc_states']) = await prover_get_entities_from_ledger(sig['pool'], sig['did'], sig['creds_for_cred_proof'],
                                                                                                              None, requested_timestamp)

    print("Two Sigma -> Create KYC Credential Proof")
    revoc_states_for_cred = json.loads(sig['cred_revoc_states'])
    timestamp_for_attr1 = get_timestamp_for_attribute(cred_for_attr1, revoc_states_for_cred)
    timestamp_for_attr2 = get_timestamp_for_attribute(cred_for_attr2, revoc_states_for_cred)
    timestamp_for_attr3 = get_timestamp_for_attribute(cred_for_attr3, revoc_states_for_cred)
    timestamp_for_attr4 = get_timestamp_for_attribute(cred_for_attr4, revoc_states_for_cred)
    timestamp_for_predicate1 = get_timestamp_for_attribute(cred_for_predicate1, revoc_states_for_cred)
    sig['cred_requested_creds'] = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True, 'timestamp': timestamp_for_attr1},
                                 'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True, 'timestamp': timestamp_for_attr2},
                                 'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True, 'timestamp': timestamp_for_attr3},
                                 'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True, 'timestamp': timestamp_for_attr4}},
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent'], 'timestamp': timestamp_for_predicate1}}
    })
    sig['cred_proof'] = await anoncreds.prover_create_proof(sig['wallet'], sig['cred_proof_request'], sig['cred_requested_creds'],
                                                            sig['master_secret_id'], sig['cred_schemas'], sig['cred_defs'], sig['cred_revoc_states'])

    print("Two Sigma -> Encrypt KYC Credential Proof")
    sig['authcrypted_cred_proof'] = await crypto.auth_crypt(sig['wallet'], sig['key_for_jp'], sig['jp_key_for_sig'], sig['cred_proof'].encode('utf-8'))

    print("Two Sigma -> Send encrypted KYC Credential Proof to JP Morgan")
    jp['authcrypted_cred_proof'] = sig['authcrypted_cred_proof']

    print("========================================")


async def jp___decrypt_cred_proof_from_sig__verify_cred_proof(jp, revoked):
    print("JP Morgan -> Decrypt KYC Credential Proof from Two Sigma")
    (_, jp['cred_proof'], cred_proof) = await auth_decrypt(jp['wallet'], jp['key_for_sig'], jp['authcrypted_cred_proof'])
    requested_timestamp = int(json.loads(jp['cred_proof_request'])['non_revoked']['to'])
    (jp['cred_schemas'], jp['cred_defs'], jp['cred_revoc_ref_defs'], jp['cred_revoc_regs']) = await verifier_get_entities_from_ledger(jp['pool'], jp['did'], cred_proof['identifiers'],
                                                                                                                                      requested_timestamp)

    if revoked:
        print("JP Morgan -> Verify KYC Credentials are revoked")
        assert not await anoncreds.verifier_verify_proof(jp['cred_proof_request'], jp['cred_proof'], jp['cred_schemas'], jp['cred_defs'], jp['cred_revoc_ref_defs'], jp['cred_revoc_regs'])
    else:
        print("JP Morgan -> Verify KYC Credentials are valid")
        assert await anoncreds.verifier_verify_proof(jp['cred_proof_request'], jp['cred_proof'], jp['cred_schemas'], jp['cred_defs'], jp['cred_revoc_ref_defs'], jp['cred_revoc_regs'])

        print("JP Morgan -> Verify KYC Credential Proof")
        assert 'Two Sigma Coop.' == cred_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
        assert '1102' == cred_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
        assert '207A, Mulberry Woods, New York' == cred_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
        assert '2.8' == cred_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']

    print("========================================")


async def gs___revoke_cred_for_sig__post_revocation_registry_delta_to_ledger(gs):
    print("Goldman Sachs -> Revoke KYC Credential for Two Sigma")
    gs['cred_rev_reg_delta'] = await anoncreds.issuer_revoke_credential(gs['wallet'], gs['blob_storage_reader_cfg_handle'], gs['cred_revoc_reg_id'], gs['cred_rev_id'])

    print("Goldman Sachs -> Post Revocation Registry Delta to Ledger")
    await send_revoc_reg_entry_or_delta(gs['pool'], gs['wallet'], gs['did'], gs['cred_revoc_reg_id'], gs['cred_rev_reg_delta'])

    print("========================================")


async def system___tear_down(pool_, gov, gs, jp, sig):
    print("Close and Delete Pool")
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    print("Close and Delete Government\'s Wallet")
    await wallet.close_wallet(gov['wallet'])
    await wallet.delete_wallet(gov['wallet_config'], gov['wallet_credentials'])

    print("Close and Delete Goldman Sachs\'s Wallet")
    await wallet.close_wallet(gs['wallet'])
    await wallet.delete_wallet(gs['wallet_config'], gs['wallet_credentials'])

    print("Close and Delete JP Morgan\'s Wallet")
    await wallet.close_wallet(jp['wallet'])
    await wallet.delete_wallet(jp['wallet_config'], jp['wallet_credentials'])

    print("Close and Delete Two Sigma\'s Wallet")
    await wallet.close_wallet(sig['wallet'])
    await wallet.delete_wallet(sig['wallet_config'], sig['wallet_credentials'])


async def get_pseudonym(_from, _to):
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


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, timestamp_from=None, timestamp_to=None):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            (rev_reg_id, revoc_reg_def_json) = await get_revoc_reg_def(pool_handle, _did, item['rev_reg_id'])
            if not timestamp_to: timestamp_to = int(time.time())
            (rev_reg_id, revoc_reg_delta_json, t) = await get_revoc_reg_delta(pool_handle, _did, item['rev_reg_id'], timestamp_from, timestamp_to)
            tails_reader_config = json.dumps({'base_dir': dirname(json.loads(revoc_reg_def_json)['value']['tailsLocation']), 'uri_pattern': ''})
            blob_storage_reader_cfg_handle = await blob_storage.open_reader('default', tails_reader_config)
            rev_state_json = await anoncreds.create_revocation_state(blob_storage_reader_cfg_handle, revoc_reg_def_json, revoc_reg_delta_json, t, item['cred_rev_id'])
            rev_states[rev_reg_id] = {t: json.loads(rev_state_json)}

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, timestamp=None):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            (rev_reg_id, revoc_reg_def_json) = await get_revoc_reg_def(pool_handle, _did, item['rev_reg_id'])
            if not timestamp: timestamp = item['timestamp']
            (rev_reg_id, rev_reg_json, timestamp2) = await get_revoc_reg(pool_handle, _did, item['rev_reg_id'], timestamp)
            rev_regs[rev_reg_id] = {timestamp2: json.loads(rev_reg_json)}
            rev_reg_defs[rev_reg_id] = json.loads(revoc_reg_def_json)

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def auth_decrypt(wallet_handle, key, message):
    from_verkey, decrypted_message_json = await crypto.auth_decrypt(wallet_handle, key, message)
    decrypted_message_json = decrypted_message_json.decode("utf-8")
    decrypted_message = json.loads(decrypted_message_json)
    return from_verkey, decrypted_message_json, decrypted_message


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)


async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, cred_def_request)


async def send_revoc_reg_def(pool_handle, wallet_handle, _did, revoc_reg_def):
    revoc_reg_def_request = await ledger.build_revoc_reg_def_request(_did, revoc_reg_def)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, revoc_reg_def_request)


async def send_revoc_reg_entry_or_delta(pool_handle, wallet_handle, _did, revoc_reg_id, revoc_reg_entry_or_delta):
    revoc_reg_entry_request = await ledger.build_revoc_reg_entry_request(_did, revoc_reg_id, 'CL_ACCUM', revoc_reg_entry_or_delta)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, revoc_reg_entry_request)


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
    return await ledger.parse_get_schema_response(get_schema_response)


async def get_cred_def(pool_handle, _did, cred_def_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, cred_def_id)
    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_revoc_reg_def(pool_handle, _did, revoc_reg_id):
    get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, revoc_reg_id)
    get_revoc_reg_def_response = await ledger.submit_request(pool_handle, get_revoc_reg_def_request)
    return await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)


async def get_revoc_reg(pool_handle, _did, revoc_reg_id, timestamp):
    get_revoc_reg_request = await ledger.build_get_revoc_reg_request(_did, revoc_reg_id, timestamp)
    get_revoc_reg_response = await ledger.submit_request(pool_handle, get_revoc_reg_request)
    return await ledger.parse_get_revoc_reg_response(get_revoc_reg_response)


async def get_revoc_reg_delta(pool_handle, _did, revoc_reg_id, timestamp_from, timestamp_to):
    get_revoc_reg_delta_request = await ledger.build_get_revoc_reg_delta_request(_did, revoc_reg_id, timestamp_from, timestamp_to)
    get_revoc_reg_delta_response = await ledger.submit_request(pool_handle, get_revoc_reg_delta_request)
    return await ledger.parse_get_revoc_reg_delta_response(get_revoc_reg_delta_response)


def get_timestamp_for_attribute(cred_for_attribute, revoc_states):
    if cred_for_attribute['rev_reg_id'] in revoc_states:
        return int(next(iter(revoc_states[cred_for_attribute['rev_reg_id']])))
    else:
        return None


if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run())
    time.sleep(1)
