import asyncio
import time
import json


from indy import anoncreds, crypto, did, ledger, pool, wallet, blob_storage
from os.path import dirname


async def run():
    print('----------------------------------------')
    print('-------------- start demo --------------')
    print('----------------------------------------')
    print('')

    (pool_, gov, sec, gs, jp, sig) = await system___set_up()

    await schema_creater___create_cred_schema__post_cred_schema_to_ledger__send_cred_schema_id_to_issuer(gov, sec)
    await schema_creater___create_cred_schema__post_cred_schema_to_ledger__send_cred_schema_id_to_issuer(gov, gs)

    await issuer___get_cred_schema_from_ledger__create_cred_definition__post_cred_definition_to_ledger__send_cred_definition_id_to_verifier(sec, jp)
    await issuer___get_cred_schema_from_ledger__create_cred_definition__post_cred_definition_to_ledger__send_cred_definition_id_to_verifier(gs, jp)

    await issuer___create_revocation_registry__post_revocation_registry_definition_to_ledger__post_revocation_registry_entry_to_ledger(sec)
    await issuer___create_revocation_registry__post_revocation_registry_definition_to_ledger__post_revocation_registry_entry_to_ledger(gs)

    await issuer___establish_connection_with_owner__create_cred_offer__encrypt_cred_offer__send_cred_offer_to_owner(sec, sig)
    await issuer___establish_connection_with_owner__create_cred_offer__encrypt_cred_offer__send_cred_offer_to_owner(gs, sig)

    await owner___decrypt_cred_offer_from_issuer__create_cred_request__encrypt_cred_request__send_cred_request_to_issuer(sig, sec)
    await owner___decrypt_cred_offer_from_issuer__create_cred_request__encrypt_cred_request__send_cred_request_to_issuer(sig, gs)

    await issuer___decrypt_cred_request_from_owner__create_cred__encrypt_cred__send_cred_to_owner__post_revocation_registry_delta_to_ledger(sec, sig)
    await issuer___decrypt_cred_request_from_owner__create_cred__encrypt_cred__send_cred_to_owner__post_revocation_registry_delta_to_ledger(gs, sig)

    await owner___decrypt_cred_from_issuer__store_cred_in_wallet(sig, sec)
    await owner___decrypt_cred_from_issuer__store_cred_in_wallet(sig, gs)

    await verifier___establish_connection_with_owner__create_cred_proof_request__encrypt_cred_proof_request__send_cred_proof_request_to_owner(jp, sig)

    await owner___decrypt_cred_proof_request_from_verifier__create_cred_proof__encrypt_cred_proof__send_cred_proof_to_verifier(sig, jp)

    await verifier___decrypt_cred_proof_from_owner__verify_cred_proof(jp, sig, False)

    await issuer___revoke_cred_for_owner__post_revocation_registry_delta_to_ledger(gs, sig)

    await verifier___establish_connection_with_owner__create_cred_proof_request__encrypt_cred_proof_request__send_cred_proof_request_to_owner(jp, sig)

    await owner___decrypt_cred_proof_request_from_verifier__create_cred_proof__encrypt_cred_proof__send_cred_proof_to_verifier(sig, jp)

    await verifier___decrypt_cred_proof_from_owner__verify_cred_proof(jp, sig, True)

    await system___tear_down(pool_, gov, sec, gs, jp, sig)

    print('----------------------------------------')
    print('--------------- end demo ---------------')
    print('----------------------------------------')


async def system___set_up():
    print('initialize pool (blockchain ledger)')
    await pool.set_protocol_version(2)
    pool_ = {
        'name': 'pool1',
        # 'config': json.dumps({'genesis_txn': '/var/lib/indy/sandbox/pool_transactions_genesis'})
        'config': json.dumps({'genesis_txn': '/home/indy/sandbox/pool_transactions_genesis'})
    }
    await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print('initialize gov (kyc credential schema creater)')
    gov = {
        'name': 'gov',
        'wallet_config': json.dumps({'id': 'gov_wallet'}),
        'wallet_credentials': json.dumps({'key': 'gov_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1',
        'sec_cred_schema': {'name': 'sec_kyc',
                            'version': '1.0',
                            'attributes': ['legalName', 'primarySicCode', 'address']},
        'gs_cred_schema': {'name': 'gs_kyc',
                           'version': '1.0',
                           'attributes': ['liquidity', 'rating']}
    }
    await wallet.create_wallet(gov['wallet_config'], gov['wallet_credentials'])
    gov['wallet'] = await wallet.open_wallet(gov['wallet_config'], gov['wallet_credentials'])
    gov['did_info'] = json.dumps({'seed': gov['seed']})
    (gov['did'], gov['key']) = await did.create_and_store_my_did(gov['wallet'], gov['did_info'])

    print('initialize sec (kyc credential issuer)')
    sec = {
        'name': 'sec',
        'wallet_config': json.dumps({'id': 'sec_wallet'}),
        'wallet_credentials': json.dumps({'key': 'sec_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR',
        'cred_def': {'tag': 'sec_tag',
                     'type': 'CL',
                     'config': {'support_revocation': True}},
        'cred_values': {'legalName': {'raw': 'Two Sigma Coop.', 'encoded': '00010203040506070809'},
                        'primarySicCode': {'raw': '1102', 'encoded': '1102'},
                        'address': {'raw': '207A, Mulberry Woods, New York', 'encoded': '20212223242526272829'}},
        'tag': 'sec_tag',
        'tails_config': json.dumps({'base_dir': '/tmp/indy_sec_tails', 'uri_pattern': ''})
    }
    await get_pseudonym(gov, sec)
    await get_verinym(gov, sec)

    print('initialize gs (kyc credential issuer)')
    gs = {
        'name': 'gs',
        'wallet_config': json.dumps({'id': 'gs_wallet'}),
        'wallet_credentials': json.dumps({'key': 'gs_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR',
        'cred_def': {'tag': 'gs_tag',
                     'type': 'CL',
                     'config': {'support_revocation': True}},
        'cred_values': {'liquidity': {'raw': '2.8', 'encoded': '2.8'},
                        'rating': {'raw': '4', 'encoded': '4'}},
        'tag': 'gs_tag',
        'tails_config': json.dumps({'base_dir': '/tmp/indy_gs_tails', 'uri_pattern': ''})
    }
    await get_pseudonym(gov, gs)
    await get_verinym(gov, gs)

    print('initialize jp (kyc credential verifier)')
    jp = {
        'name': 'jp',
        'wallet_config': json.dumps({'id': 'jp_wallet'}),
        'wallet_credentials': json.dumps({'key': 'jp_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    await get_pseudonym(gov, jp)
    await get_verinym(gov, jp)

    print('initialize sig (kyc credential owner)')
    sig = {
        'name': 'sig',
        'wallet_config': json.dumps({'id': 'sig_wallet'}),
        'wallet_credentials': json.dumps({'key': 'sig_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    await get_pseudonym(gov, sig)
    await get_verinym(gov, sig)
    sig['master_secret_id'] = await anoncreds.prover_create_master_secret(sig['wallet'], None)

    print('----------------------------------------')
    input('')

    return (pool_, gov, sec, gs, jp, sig)


async def schema_creater___create_cred_schema__post_cred_schema_to_ledger__send_cred_schema_id_to_issuer(schema_creater, issuer):
    schema_creater_name = schema_creater['name']
    issuer_name = issuer['name']

    cred_schema = schema_creater[issuer_name + '_cred_schema']
    print(schema_creater_name + ' | creates kyc credential schema: ' + str(cred_schema['attributes']))
    (cred_schema_id, cred_schema) = await anoncreds.issuer_create_schema(schema_creater['did'], cred_schema['name'], cred_schema['version'], json.dumps(cred_schema['attributes']))

    print(schema_creater_name + ' | posts kyc credential schema to ledger')
    await send_schema(schema_creater['pool'], schema_creater['wallet'], schema_creater['did'], cred_schema)

    print(schema_creater_name + ' | sends kyc credential schema id to ' + issuer_name)
    issuer['cred_schema_id'] = cred_schema_id

    print('----------------------------------------')
    input('')


async def issuer___get_cred_schema_from_ledger__create_cred_definition__post_cred_definition_to_ledger__send_cred_definition_id_to_verifier(issuer, verifier):
    issuer_name = issuer['name']
    verifier_name = verifier['name']

    print(issuer_name + ' | gets kyc schema from Ledger')
    (_, issuer['cred_schema']) = await get_schema(issuer['pool'], issuer['did'], issuer['cred_schema_id'])

    print(issuer_name + ' | creates kyc credential definition')
    cred_def = issuer['cred_def']
    (issuer['cred_def_id'], issuer['cred_def']) = await anoncreds.issuer_create_and_store_credential_def(issuer['wallet'], issuer['did'], issuer['cred_schema'], cred_def['tag'],
                                                                                                         cred_def['type'], json.dumps(cred_def['config']))

    print(issuer_name + ' | posts kyc credential definition to ledger')
    await send_cred_def(issuer['pool'], issuer['wallet'], issuer['did'], issuer['cred_def'])

    print(issuer_name + ' | sends kyc credential definition id to ' + verifier_name)
    verifier[issuer_name + '_cred_def_id'] = issuer['cred_def_id']

    print('----------------------------------------')
    input('')


async def issuer___create_revocation_registry__post_revocation_registry_definition_to_ledger__post_revocation_registry_entry_to_ledger(issuer):
    issuer_name = issuer['name']

    print(issuer_name + ' | creates revocation registry')
    tails_config_writer = await blob_storage.open_writer('default', issuer['tails_config'])
    (issuer['cred_revoc_reg_id'], issuer['cred_revoc_reg_def'], issuer['cred_revoc_reg_entry']) = await anoncreds.issuer_create_and_store_revoc_reg(issuer['wallet'], issuer['did'],
                                                                                                                                                    'CL_ACCUM', issuer['tag'],
                                                                                                                                                    issuer['cred_def_id'], '{}',
                                                                                                                                                    tails_config_writer)

    print(issuer_name + ' | posts revocation registry definition to ledger')
    await send_revoc_reg_def(issuer['pool'], issuer['wallet'], issuer['did'], issuer['cred_revoc_reg_def'])

    print(issuer_name + ' | posts revocation registry entry to ledger')
    await send_revoc_reg_entry_or_delta(issuer['pool'], issuer['wallet'], issuer['did'], issuer['cred_revoc_reg_id'], issuer['cred_revoc_reg_entry'])

    print('----------------------------------------')
    input('')


async def issuer___establish_connection_with_owner__create_cred_offer__encrypt_cred_offer__send_cred_offer_to_owner(issuer, owner):
    issuer_name = issuer['name']
    owner_name = owner['name']

    await get_pseudonym(issuer, owner)

    print(issuer_name + ' | creates kyc credential offer for ' + owner_name)
    issuer['cred_offer'] = await anoncreds.issuer_create_credential_offer(issuer['wallet'], issuer['cred_def_id'])

    print(issuer_name + ' | encrypts kyc credential offer')
    key = await did.key_for_did(issuer['pool'], issuer['wallet'], issuer[owner_name + '_connection_response']['did'])
    issuer['authcrypted_cred_offer'] = await crypto.auth_crypt(issuer['wallet'], issuer['key_for_' + owner_name], key, issuer['cred_offer'].encode('utf-8'))

    print(issuer_name + ' | sends encrypted kyc credential offer to ' + owner_name)
    owner[issuer_name + '_authcrypted_cred_offer'] = issuer['authcrypted_cred_offer']

    print('----------------------------------------')
    input('')


async def owner___decrypt_cred_offer_from_issuer__create_cred_request__encrypt_cred_request__send_cred_request_to_issuer(owner, issuer):
    owner_name = owner['name']
    issuer_name = issuer['name']

    print(owner_name + ' | decrypts kyc credential offer from ' + issuer_name)
    (key, owner[issuer_name + '_cred_offer'], authdecrypted_cred_offer) = await auth_decrypt(owner['wallet'], owner['key_for_' + issuer_name],
                                                                                             owner[issuer_name + '_authcrypted_cred_offer'])
    owner[issuer_name + '_cred_def_id'] = authdecrypted_cred_offer['cred_def_id']

    print(owner_name + ' | creates kyc credential request')
    (owner[issuer_name + '_cred_def_id'], owner[issuer_name + '_cred_def']) = await get_cred_def(owner['pool'], owner['did'], owner[issuer_name + '_cred_def_id'])
    (owner[issuer_name + '_cred_request'], owner[issuer_name + '_cred_request_metadata']) = await anoncreds.prover_create_credential_req(owner['wallet'], owner['did'],
                                                                                                                                         owner[issuer_name + '_cred_offer'],
                                                                                                                                         owner[issuer_name + '_cred_def'],
                                                                                                                                         owner['master_secret_id'])

    print(owner_name + ' | encrypts kyc credential request')
    owner[issuer_name + '_authcrypted_cred_request'] = await crypto.auth_crypt(owner['wallet'], owner['key_for_' + issuer_name], key, owner[issuer_name + '_cred_request'].encode('utf-8'))

    print(owner_name + ' | sends encrypted kyc credential request to ' + issuer_name)
    issuer['authcrypted_cred_request'] = owner[issuer_name + '_authcrypted_cred_request']

    print('----------------------------------------')
    input('')


async def issuer___decrypt_cred_request_from_owner__create_cred__encrypt_cred__send_cred_to_owner__post_revocation_registry_delta_to_ledger(issuer, owner):
    issuer_name = issuer['name']
    owner_name = owner['name']

    print(issuer_name + ' | decrypts kyc credential request from ' + owner_name)
    (key, issuer['cred_request'], _) = await auth_decrypt(issuer['wallet'], issuer['key_for_' + owner_name], issuer['authcrypted_cred_request'])

    print(issuer_name + ' | creates kyc credential : ' + str(issuer['cred_values']))
    tails_config_reader = await blob_storage.open_reader('default', issuer['tails_config'])
    (issuer['cred'], issuer['cred_rev_id'], issuer['cred_rev_reg_delta']) = await anoncreds.issuer_create_credential(issuer['wallet'], issuer['cred_offer'],
                                                                                                                     issuer['cred_request'], json.dumps(issuer['cred_values']),
                                                                                                                     issuer['cred_revoc_reg_id'], tails_config_reader)

    print(issuer_name + ' | encrypts kyc credential')
    issuer['authcrypted_cred'] = await crypto.auth_crypt(issuer['wallet'], issuer['key_for_' + owner_name], key, issuer['cred'].encode('utf-8'))

    print(issuer_name + ' | sends encrypted kyc credential to ' + owner_name)
    owner[issuer_name + '_authcrypted_cred'] = issuer['authcrypted_cred']

    print(issuer_name + ' | posts revocation registry delta to ledger')
    await send_revoc_reg_entry_or_delta(issuer['pool'], issuer['wallet'], issuer['did'], issuer['cred_revoc_reg_id'], issuer['cred_rev_reg_delta'])

    print('----------------------------------------')
    input('')


async def owner___decrypt_cred_from_issuer__store_cred_in_wallet(owner, issuer):
    owner_name = owner['name']
    issuer_name = issuer['name']

    print(owner_name + ' | decrypts kyc credential from ' + issuer_name)
    (_, owner[issuer_name + '_cred'], cred) = await auth_decrypt(owner['wallet'], owner['key_for_' + issuer_name], owner[issuer_name + '_authcrypted_cred'])

    print(owner_name + ' | stores kyc credential in wallet')
    (_, owner[issuer_name + '_cred_def']) = await get_cred_def(owner['pool'], owner['did'], owner[issuer_name + '_cred_def_id'])
    (_, owner[issuer_name + '_revoc_reg_def_json']) = await get_revoc_reg_def(owner['pool'], owner['did'], cred['rev_reg_id'])
    await anoncreds.prover_store_credential(owner['wallet'], None, owner[issuer_name + '_cred_request_metadata'], owner[issuer_name + '_cred'],
                                            owner[issuer_name + '_cred_def'], owner[issuer_name + '_revoc_reg_def_json'])

    print('----------------------------------------')
    input('')


async def verifier___establish_connection_with_owner__create_cred_proof_request__encrypt_cred_proof_request__send_cred_proof_request_to_owner(verifier, owner):
    verifier_name = verifier['name']
    owner_name = owner['name']

    await get_pseudonym(verifier, owner)

    print(verifier_name + ' | creates kyc credential proof request : {legalName, primarySicCode, address, liquidity, rating>=3}')
    nonce = await anoncreds.generate_nonce()
    verifier['cred_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'KYC Credential',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'legalName',
                'restrictions': [{'cred_def_id': verifier['sec_cred_def_id']}]
            },
            'attr2_referent': {
                'name': 'primarySicCode',
                'restrictions': [{'cred_def_id': verifier['sec_cred_def_id']}]
            },
            'attr3_referent': {
                'name': 'address',
                'restrictions': [{'cred_def_id': verifier['sec_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'liquidity',
                'restrictions': [{'cred_def_id': verifier['gs_cred_def_id']}]
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'rating',
                'p_type': '>=',
                'p_value': 3,
                'restrictions': [{'cred_def_id': verifier['gs_cred_def_id']}]
            }
        },
        'non_revoked': {'to': int(time.time())}
    })

    print(verifier_name + ' | encrypts kyc credential proof request')
    key = await did.key_for_did(verifier['pool'], verifier['wallet'], verifier[owner_name + '_connection_response']['did'])
    verifier['authcrypted_cred_proof_request'] = await crypto.auth_crypt(verifier['wallet'], verifier['key_for_' + owner_name], key, verifier['cred_proof_request'].encode('utf-8'))

    print(verifier_name + ' | sends encrypted kyc credential proof request to ' + owner_name)
    owner['authcrypted_cred_proof_request'] = verifier['authcrypted_cred_proof_request']

    print('----------------------------------------')
    input('')


async def owner___decrypt_cred_proof_request_from_verifier__create_cred_proof__encrypt_cred_proof__send_cred_proof_to_verifier(owner, verifier):
    owner_name = owner['name']
    verifier_name = verifier['name']

    print(owner_name + ' | decrypts kyc credential proof request from ' + verifier_name)
    (key, owner['cred_proof_request'], _) = await auth_decrypt(owner['wallet'], owner['key_for_' + verifier_name], owner['authcrypted_cred_proof_request'])

    print(owner_name + ' | gets credentials for kyc credential proof request')
    requested_credentials = json.loads(await anoncreds.prover_get_credentials_for_proof_req(owner['wallet'], owner['cred_proof_request']))
    cred_for_attr1 = requested_credentials['attrs']['attr1_referent'][0]['cred_info']
    cred_for_attr2 = requested_credentials['attrs']['attr2_referent'][0]['cred_info']
    cred_for_attr3 = requested_credentials['attrs']['attr3_referent'][0]['cred_info']
    cred_for_attr4 = requested_credentials['attrs']['attr4_referent'][0]['cred_info']
    cred_for_predicate1 = requested_credentials['predicates']['predicate1_referent'][0]['cred_info']
    owner['creds_for_cred_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                     cred_for_attr2['referent']: cred_for_attr2,
                                     cred_for_attr3['referent']: cred_for_attr3,
                                     cred_for_attr4['referent']: cred_for_attr4,
                                     cred_for_predicate1['referent']: cred_for_predicate1}
    requested_timestamp = int(json.loads(owner['cred_proof_request'])['non_revoked']['to'])
    (owner['cred_schemas'], owner['cred_defs'], owner['cred_revoc_states']) = await prover_get_entities_from_ledger(owner['pool'], owner['did'], owner['creds_for_cred_proof'],
                                                                                                                    None, requested_timestamp)

    print(owner_name + ' | creates kyc credential proof')
    revoc_states_for_cred = json.loads(owner['cred_revoc_states'])
    timestamp_for_attr1 = get_timestamp_for_attribute(cred_for_attr1, revoc_states_for_cred)
    timestamp_for_attr2 = get_timestamp_for_attribute(cred_for_attr2, revoc_states_for_cred)
    timestamp_for_attr3 = get_timestamp_for_attribute(cred_for_attr3, revoc_states_for_cred)
    timestamp_for_attr4 = get_timestamp_for_attribute(cred_for_attr4, revoc_states_for_cred)
    timestamp_for_predicate1 = get_timestamp_for_attribute(cred_for_predicate1, revoc_states_for_cred)
    owner['cred_requested_creds'] = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True, 'timestamp': timestamp_for_attr1},
                                 'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True, 'timestamp': timestamp_for_attr2},
                                 'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True, 'timestamp': timestamp_for_attr3},
                                 'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True, 'timestamp': timestamp_for_attr4}},
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent'], 'timestamp': timestamp_for_predicate1}}
    })
    owner['cred_proof'] = await anoncreds.prover_create_proof(owner['wallet'], owner['cred_proof_request'], owner['cred_requested_creds'],
                                                              owner['master_secret_id'], owner['cred_schemas'], owner['cred_defs'], owner['cred_revoc_states'])

    print(owner_name + ' | encrypts kyc credential proof')
    owner['authcrypted_cred_proof'] = await crypto.auth_crypt(owner['wallet'], owner['key_for_' + verifier_name], key, owner['cred_proof'].encode('utf-8'))

    print(owner_name + ' | sends encrypted kyc credential proof to ' + verifier_name)
    verifier['authcrypted_cred_proof'] = owner['authcrypted_cred_proof']

    print('----------------------------------------')
    input('')


async def verifier___decrypt_cred_proof_from_owner__verify_cred_proof(verifier, owner, revoked):
    verifier_name = verifier['name']
    owner_name = owner['name']

    print(verifier_name + ' | decrypts kyc credential proof from ' + owner_name)
    (_, verifier['cred_proof'], cred_proof) = await auth_decrypt(verifier['wallet'], verifier['key_for_' + owner_name], verifier['authcrypted_cred_proof'])
    requested_timestamp = int(json.loads(verifier['cred_proof_request'])['non_revoked']['to'])
    (verifier['cred_schemas'], verifier['cred_defs'], verifier['cred_revoc_ref_defs'], verifier['cred_revoc_regs']) = await verifier_get_entities_from_ledger(verifier['pool'],
                                                                                                                                                              verifier['did'],
                                                                                                                                                              cred_proof['identifiers'],
                                                                                                                                                              requested_timestamp)

    if revoked:
        print(verifier_name + ' | verifies kyc credentials are revoked')
        assert not await anoncreds.verifier_verify_proof(verifier['cred_proof_request'], verifier['cred_proof'], verifier['cred_schemas'],
                                                         verifier['cred_defs'], verifier['cred_revoc_ref_defs'], verifier['cred_revoc_regs'])
    else:
        print(verifier_name + ' | verifies kyc credentials are valid')
        assert await anoncreds.verifier_verify_proof(verifier['cred_proof_request'], verifier['cred_proof'], verifier['cred_schemas'],
                                                     verifier['cred_defs'], verifier['cred_revoc_ref_defs'], verifier['cred_revoc_regs'])

        print(verifier_name + ' | verifies kyc credential proof values')
        assert 'Two Sigma Coop.' == cred_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
        assert '1102' == cred_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
        assert '207A, Mulberry Woods, New York' == cred_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
        assert '2.8' == cred_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']

    print('----------------------------------------')
    input('')


async def issuer___revoke_cred_for_owner__post_revocation_registry_delta_to_ledger(issuer, owner):
    issuer_name = issuer['name']
    owner_name = owner['name']

    print(issuer_name + ' | revokes kyc credential for ' + owner_name)
    tails_config_reader = await blob_storage.open_reader('default', issuer['tails_config'])
    issuer['cred_rev_reg_delta'] = await anoncreds.issuer_revoke_credential(issuer['wallet'], tails_config_reader, issuer['cred_revoc_reg_id'], issuer['cred_rev_id'])

    print(issuer_name + ' | posts revocation registry delta to ledger')
    await send_revoc_reg_entry_or_delta(issuer['pool'], issuer['wallet'], issuer['did'], issuer['cred_revoc_reg_id'], issuer['cred_rev_reg_delta'])

    print('----------------------------------------')
    input('')


async def system___tear_down(pool_, gov, sec, gs, jp, sig):
    print('close and delete pool')
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    print('close and delete gov\'s wallet')
    await wallet.close_wallet(gov['wallet'])
    await wallet.delete_wallet(gov['wallet_config'], gov['wallet_credentials'])

    print('close and delete sec\'s wallet')
    await wallet.close_wallet(sec['wallet'])
    await wallet.delete_wallet(sec['wallet_config'], sec['wallet_credentials'])

    print('close and delete gs\'s wallet')
    await wallet.close_wallet(gs['wallet'])
    await wallet.delete_wallet(gs['wallet_config'], gs['wallet_credentials'])

    print('close and delete jp\'s wallet')
    await wallet.close_wallet(jp['wallet'])
    await wallet.delete_wallet(jp['wallet_config'], jp['wallet_credentials'])

    print('close and delete sig\'s wallet')
    await wallet.close_wallet(sig['wallet'])
    await wallet.delete_wallet(sig['wallet_config'], sig['wallet_credentials'])

    print('----------------------------------------')
    input('')


async def from___create_did_and_key__post_did_and_key_to_ledger__send_did_and_nonce_to_to(_from, _to):
    from_name = _from['name']
    to_name = _to['name']
    did_for_to = 'did_for_' + to_name
    key_for_to = 'key_for_' + to_name
    (_from[did_for_to], _from[key_for_to]) = await did.create_and_store_my_did(_from['wallet'], '{}')
    await send_nym(_from['pool'], _from['wallet'], _from['did'], _from[did_for_to], _from[key_for_to], None)

    nonce = await anoncreds.generate_nonce()
    _from['connection_request'] = {'did': _from[did_for_to], 'nonce': nonce}
    _to[from_name + '_connection_request'] = _from['connection_request']


async def to___create_wallet__create_did_and_key__encrypt_did_and_key_and_nonce__send_did_and_key_and_nonce_to_from(_to, _from):
    if 'wallet' not in _to:
        await wallet.create_wallet(_to['wallet_config'], _to['wallet_credentials'])
        _to['wallet'] = await wallet.open_wallet(_to['wallet_config'], _to['wallet_credentials'])

    to_name = _to['name']
    from_name = _from['name']
    did_for_from = 'did_for_' + from_name
    key_for_from = 'key_for_' + from_name
    (_to[did_for_from], _to[key_for_from]) = await did.create_and_store_my_did(_to['wallet'], '{}')

    _to['connection_response'] = json.dumps({
        'did': _to[did_for_from],
        'key': _to[key_for_from],
        'nonce': _to[from_name + '_connection_request']['nonce']
    })
    _to['key_of_from_for_to'] = await did.key_for_did(_to['pool'], _to['wallet'], _to[from_name + '_connection_request']['did'])
    _to['anoncrypted_connection_response'] = await crypto.anon_crypt(_to['key_of_from_for_to'], _to['connection_response'].encode('utf-8'))

    _from[to_name + '_anoncrypted_connection_response'] = _to['anoncrypted_connection_response']


async def from___decrypt_did_and_key_and_nonce__verify_nonce__post_did_and_key_to_ledger(_from, _to):
    to_name = _to['name']
    key_for_to = 'key_for_' + to_name
    _from[to_name + '_connection_response'] = json.loads((await crypto.anon_decrypt(_from['wallet'], _from[key_for_to],
                                                                                    _from[to_name + '_anoncrypted_connection_response'])).decode('utf-8'))

    assert _from['connection_request']['nonce'] == _from[to_name + '_connection_response']['nonce']

    await send_nym(_from['pool'], _from['wallet'], _from['did'], _from[to_name + '_connection_response']['did'], _from[to_name + '_connection_response']['key'], None)


async def to___create_did_and_key__encrypt_did_and_key_and_role__send_did_and_key_and_role_to_from(_to, _from):
    (_to['did'], _to['key']) = await did.create_and_store_my_did(_to['wallet'], '{}')

    _to['did_info'] = json.dumps({'did': _to['did'], 'key': _to['key'], 'role': _to['role']}).encode('utf-8')
    to_name = _to['name']
    from_name = _from['name']
    key_for_from = 'key_for_' + from_name
    _to['authcrypted_did_info'] = await crypto.auth_crypt(_to['wallet'], _to[key_for_from], _to['key_of_from_for_to'], _to['did_info'])

    _from[to_name + '_authcrypted_did_info'] = _to['authcrypted_did_info']


async def from___decrypt_did_and_key_and_role__verify_key__post_did_and_key_and_role_to_leger(_from, _to):
    to_name = _to['name']
    key_for_to = 'key_for_' + to_name
    (sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info) = await auth_decrypt(_from['wallet'], _from[key_for_to], _from[to_name + '_authcrypted_did_info'])

    assert sender_verkey == await did.key_for_did(_from['pool'], _from['wallet'], _from[to_name + '_connection_response']['did'])

    await send_nym(_from['pool'], _from['wallet'], _from['did'], authdecrypted_did_info['did'], authdecrypted_did_info['key'], authdecrypted_did_info['role'])


async def get_pseudonym(_from, _to):
    await from___create_did_and_key__post_did_and_key_to_ledger__send_did_and_nonce_to_to(_from, _to)
    await to___create_wallet__create_did_and_key__encrypt_did_and_key_and_nonce__send_did_and_key_and_nonce_to_from(_to, _from)
    await from___decrypt_did_and_key_and_nonce__verify_nonce__post_did_and_key_to_ledger(_from, _to)


async def get_verinym(_from, _to):
    await to___create_did_and_key__encrypt_did_and_key_and_role__send_did_and_key_and_role_to_from(_to, _from)
    await from___decrypt_did_and_key_and_role__verify_key__post_did_and_key_and_role_to_leger(_from, _to)


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
    decrypted_message_json = decrypted_message_json.decode('utf-8')
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
