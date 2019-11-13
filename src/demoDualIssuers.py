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

    print(tab + 'System -> Create pool with ledger config')
    try:
        await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass

    print(tab + 'System -> Open pool')
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print("Initialize Government")
    government = {
        'name': "government",
        'wallet_config': json.dumps({'id': 'government_wallet'}),
        'wallet_credentials': json.dumps({'key': 'government_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }

    print(tab + 'Government -> Create wallet')
    try:
        await wallet.create_wallet(government['wallet_config'], government['wallet_credentials'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass
    government['wallet'] = await wallet.open_wallet(government['wallet_config'], government['wallet_credentials'])

    print(tab + 'Government -> Create did and key and store in wallet')
    government['did_info'] = json.dumps({'seed': government['seed']})
    (government['did'], government['key']) = await did.create_and_store_my_did(government['wallet'], government['did_info'])

    print('Initialize SEC')
    sec = {
        'name': 'sec',
        'wallet_config': json.dumps({'id': 'sec_wallet'}),
        'wallet_credentials': json.dumps({'key': 'sec_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    (government['did_for_sec'],
     government['key_for_sec'],
     sec['did_for_government'],
     sec['key_for_government'], _) = await onboarding(government, sec)

    sec['did'] = await get_verinym(government, sec)

    print('Initialize General Auditor')
    general_auditor = {
        'name': 'general_auditor',
        'wallet_config': json.dumps({'id': 'general_auditor_wallet'}),
        'wallet_credentials': json.dumps({'key': 'general_auditor_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    (government['did_for_general_auditor'],
     government['key_for_general_auditor'],
     general_auditor['did_for_government'],
     general_auditor['key_for_government'], _) = await onboarding(government, general_auditor)

    general_auditor['did'] = await get_verinym(government, general_auditor)

    print('Initialize Financial Auditor')
    financial_auditor = {
        'name': 'financial_auditor',
        'wallet_config': json.dumps({'id': 'financial_auditor_wallet'}),
        'wallet_credentials': json.dumps({'key': 'financial_auditor_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    (government['did_for_financial_auditor'],
     government['key_for_financial_auditor'],
     financial_auditor['did_for_government'],
     financial_auditor['key_for_government'], _) = await onboarding(government, financial_auditor)

    financial_auditor['did'] = await get_verinym(government, financial_auditor)

    print('Initialize Goldman Sachs')
    goldman_sachs = {
        'name': 'goldman_sachs',
        'wallet_config': json.dumps({'id': 'goldman_sachs_wallet'}),
        'wallet_credentials': json.dumps({'key': 'goldman_sachs_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    (government['did_for_goldman_sachs'],
     government['key_for_goldman_sachs'],
     goldman_sachs['did_for_government'],
     goldman_sachs['key_for_government'], _) = await onboarding(government, goldman_sachs)

    goldman_sachs['did'] = await get_verinym(government, goldman_sachs)

    print()
    print("========================================")
    print("============== Start Demo ==============")
    print("========================================")

    print("SEC -> Create General KYC Credential Schema")
    general_kyc = {
        'name': 'General KYC',
        'version': '1.2',
        'attributes': ['id', 'legalName', 'legalOwner', 'primarySicCode', 'address']
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
        'attributes': ['taxCountry', 'industryClassificationCode', 'liquidity', 'exposureCap', 'creditRating']
    }
    (sec['financial_kyc_schema_id'], sec['financial_kyc_schema']) = await anoncreds.issuer_create_schema(sec['did'],
                                                                                                         financial_kyc['name'],
                                                                                                         financial_kyc['version'],
                                                                                                         json.dumps(financial_kyc['attributes']))
    financial_kyc_schema_id = sec['financial_kyc_schema_id']

    print("SEC -> Send Financial KYC Credential Schema to Ledger")
    await send_schema(sec['pool'], sec['wallet'], sec['did'], sec['financial_kyc_schema'])

    time.sleep(1) # sleep 1 second before getting schema

    print("========================================")

    print("General Auditor -> Get General KYC Schema from Ledger")
    (general_auditor['general_kyc_schema_id'], general_auditor['general_kyc_schema']) = await get_schema(general_auditor['pool'],
                                                                                                         general_auditor['did'],
                                                                                                         general_kyc_schema_id)

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

    print("========================================")

    print("Financial Auditor -> Get Financial KYC Schema from Ledger")
    (financial_auditor['financial_kyc_schema_id'], financial_auditor['financial_kyc_schema']) = await get_schema(financial_auditor['pool'],
                                                                                                                 financial_auditor['did'],
                                                                                                                 financial_kyc_schema_id)

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

    print("========================================")

    jp_morgan = {
        'name': 'jp_morgan',
        'wallet_config': json.dumps({'id': 'jp_morgan_wallet'}),
        'wallet_credentials': json.dumps({'key': 'jp_morgan_wallet_key'}),
        'pool': pool_['handle'],
    }
    print("General Auditor -> Establish p2p connection with JP Morgan")
    (general_auditor['did_for_jp_morgan'],
     general_auditor['key_for_jp_morgan'],
     jp_morgan['did_for_general_auditor'],
     jp_morgan['key_for_general_auditor'],
     general_auditor['jp_morgan_connection_response']) = await onboarding(general_auditor, jp_morgan)

    print("General Auditor -> Create General KYC Credential Offer for JP Morgan")
    general_auditor['general_kyc_cred_offer'] = await anoncreds.issuer_create_credential_offer(general_auditor['wallet'], general_auditor['general_kyc_cred_def_id'])

    print("General Auditor -> Encrypt General KYC Credential Offer with JP Morgan\'s key")
    general_auditor['jp_morgan_key_for_general_auditor'] = await did.key_for_did(general_auditor['pool'],
                                                                                 general_auditor['wallet'],
                                                                                 general_auditor['jp_morgan_connection_response']['did'])
    general_auditor['authcrypted_general_kyc_cred_offer'] = await crypto.auth_crypt(general_auditor['wallet'],
                                                                                    general_auditor['key_for_jp_morgan'],
                                                                                    general_auditor['jp_morgan_key_for_general_auditor'],
                                                                                    general_auditor['general_kyc_cred_offer'].encode('utf-8'))

    print("General Auditor -> Send Encrypted General KYC Credential Offer to JP Morgan")
    jp_morgan['authcrypted_general_kyc_cred_offer'] = general_auditor['authcrypted_general_kyc_cred_offer']

    print("========================================")

    print("Financial Auditor -> Establish p2p connection with JP Morgan")
    (financial_auditor['did_for_jp_morgan'],
     financial_auditor['key_for_jp_morgan'],
     jp_morgan['did_for_financial_auditor'],
     jp_morgan['key_for_financial_auditor'],
     financial_auditor['jp_morgan_connection_response']) = await onboarding(financial_auditor, jp_morgan)

    print("Financial Auditor -> Create Financial KYC Credential Offer for JP Morgan")
    financial_auditor['financial_kyc_cred_offer'] = await anoncreds.issuer_create_credential_offer(financial_auditor['wallet'], financial_auditor['financial_kyc_cred_def_id'])

    print("Financial Auditor -> Encrypt Financial KYC Credential Offer with JP Morgan\'s key")
    financial_auditor['jp_morgan_key_for_financial_auditor'] = await did.key_for_did(financial_auditor['pool'],
                                                                                     financial_auditor['wallet'],
                                                                                     financial_auditor['jp_morgan_connection_response']['did'])
    financial_auditor['authcrypted_financial_kyc_cred_offer'] = await crypto.auth_crypt(financial_auditor['wallet'],
                                                                                        financial_auditor['key_for_jp_morgan'],
                                                                                        financial_auditor['jp_morgan_key_for_financial_auditor'],
                                                                                        financial_auditor['financial_kyc_cred_offer'].encode('utf-8'))

    print("Financial Auditor -> Send Encrypted Financial KYC Credential Offer to JP Morgan")
    jp_morgan['authcrypted_financial_kyc_cred_offer'] = financial_auditor['authcrypted_financial_kyc_cred_offer']

    print("========================================")

    print("JP Morgan -> Create and Store Master Secret in Wallet")
    jp_morgan['master_secret_id'] = await anoncreds.prover_create_master_secret(jp_morgan['wallet'], None)

    print("JP Morgan -> Decrypt General KYC Credential Offer from General Auditor")
    (jp_morgan['general_auditor_key_for_jp_morgan'], jp_morgan['general_kyc_cred_offer'], authdecrypted_general_kyc_cred_offer) = await auth_decrypt(jp_morgan['wallet'],
                                                                                                                                                     jp_morgan['key_for_general_auditor'],
                                                                                                                                                     jp_morgan['authcrypted_general_kyc_cred_offer'])
    jp_morgan['general_kyc_schema_id'] = authdecrypted_general_kyc_cred_offer['schema_id']
    jp_morgan['general_kyc_cred_def_id'] = authdecrypted_general_kyc_cred_offer['cred_def_id']

    print("JP Morgan -> Get General KYC Credential Definition from Ledger")
    (jp_morgan['general_auditor_general_kyc_cred_def_id'], jp_morgan['general_auditor_general_kyc_cred_def']) = await get_cred_def(jp_morgan['pool'],
                                                                                                                                   jp_morgan['did_for_general_auditor'],
                                                                                                                                   authdecrypted_general_kyc_cred_offer['cred_def_id'])

    print("JP Morgan -> Create General KYC Credential Request for General Auditor")
    (jp_morgan['general_kyc_cred_request'], jp_morgan['general_kyc_cred_request_metadata']) = await anoncreds.prover_create_credential_req(jp_morgan['wallet'],
                                                                                                                                           jp_morgan['did_for_general_auditor'],
                                                                                                                                           jp_morgan['general_kyc_cred_offer'],
                                                                                                                                           jp_morgan['general_auditor_general_kyc_cred_def'],
                                                                                                                                           jp_morgan['master_secret_id'])

    print("JP Morgan -> Encrypt General KYC Credential Request with General Auditor\'s key")
    jp_morgan['authcrypted_general_kyc_cred_request'] = await crypto.auth_crypt(jp_morgan['wallet'],
                                                                                jp_morgan['key_for_general_auditor'],
                                                                                jp_morgan['general_auditor_key_for_jp_morgan'],
                                                                                jp_morgan['general_kyc_cred_request'].encode('utf-8'))

    print("JP Morgan -> Send encrypted General KYC Credential Request to General Auditor")
    general_auditor['authcrypted_general_kyc_cred_request'] = jp_morgan['authcrypted_general_kyc_cred_request']

    print("JP Morgan -> Decrypt Financial KYC Credential Offer from Financial Auditor")
    (jp_morgan['financial_auditor_key_for_jp_morgan'], jp_morgan['financial_kyc_cred_offer'], authdecrypted_financial_kyc_cred_offer) = await auth_decrypt(jp_morgan['wallet'],
                                                                                                                                                           jp_morgan['key_for_financial_auditor'],
                                                                                                                                                           jp_morgan['authcrypted_financial_kyc_cred_offer'])
    jp_morgan['financial_kyc_schema_id'] = authdecrypted_financial_kyc_cred_offer['schema_id']
    jp_morgan['financial_kyc_cred_def_id'] = authdecrypted_financial_kyc_cred_offer['cred_def_id']

    print("JP Morgan -> Get Financial KYC Credential Definition from Ledger")
    (jp_morgan['financial_auditor_financial_kyc_cred_def_id'], jp_morgan['financial_auditor_financial_kyc_cred_def']) = await get_cred_def(jp_morgan['pool'],
                                                                                                                                           jp_morgan['did_for_financial_auditor'],
                                                                                                                                           authdecrypted_financial_kyc_cred_offer['cred_def_id'])

    print("JP Morgan -> Create Financial KYC Credential Request for Financial Auditor")
    (jp_morgan['financial_kyc_cred_request'], jp_morgan['financial_kyc_cred_request_metadata']) = await anoncreds.prover_create_credential_req(jp_morgan['wallet'],
                                                                                                                                               jp_morgan['did_for_financial_auditor'],
                                                                                                                                               jp_morgan['financial_kyc_cred_offer'],
                                                                                                                                               jp_morgan['financial_auditor_financial_kyc_cred_def'],
                                                                                                                                               jp_morgan['master_secret_id'])

    print("JP Morgan -> Encrypt Financial KYC Credential Request with Financial Auditor\'s key")
    jp_morgan['authcrypted_financial_kyc_cred_request'] = await crypto.auth_crypt(jp_morgan['wallet'],
                                                                                  jp_morgan['key_for_financial_auditor'],
                                                                                  jp_morgan['financial_auditor_key_for_jp_morgan'],
                                                                                  jp_morgan['financial_kyc_cred_request'].encode('utf-8'))

    print("JP Morgan -> Send encrypted Financial KYC Credential Request to Financial Auditor")
    financial_auditor['authcrypted_financial_kyc_cred_request'] = jp_morgan['authcrypted_financial_kyc_cred_request']

    print("========================================")

    print("General Auditor -> Decrypt General KYC Credential Request from JP Morgan")
    (general_auditor['jp_morgan_key_for_general_auditor'], general_auditor['general_kyc_cred_request'], _) = await auth_decrypt(general_auditor['wallet'],
                                                                                                                                general_auditor['key_for_jp_morgan'],
                                                                                                                                general_auditor['authcrypted_general_kyc_cred_request'])

    print("General Auditor -> Create General KYC Credential for JP Morgan")
    general_auditor['jp_morgan_general_kyc_cred_values'] = json.dumps({
        "id": {"raw": "101", "encoded": "101"},
        "legalName": {"raw": "JP Morgan Coop.", "encoded": "00010203040506070809"},
        "legalOwner": {"raw": "Mr. Morgan", "encoded": "10111213141516171819"},
        "primarySicCode": {"raw": "1102", "encoded": "1102"},
        "address": {"raw": "207A, Mulberry Woods, New York", "encoded": "20212223242526272829"}
    })
    (general_auditor['general_kyc_cred'], _, _) = await anoncreds.issuer_create_credential(general_auditor['wallet'],
                                                                                           general_auditor['general_kyc_cred_offer'],
                                                                                           general_auditor['general_kyc_cred_request'],
                                                                                           general_auditor['jp_morgan_general_kyc_cred_values'],
                                                                                           None,
                                                                                           None)

    print("General Auditor -> Encrypt General KYC Credential for JP Morgan")
    general_auditor['authcrypted_general_kyc_cred'] = await crypto.auth_crypt(general_auditor['wallet'],
                                                                              general_auditor['key_for_jp_morgan'],
                                                                              general_auditor['jp_morgan_key_for_general_auditor'],
                                                                              general_auditor['general_kyc_cred'].encode('utf-8'))

    print("General Auditor -> Send encrypted General KYC Credential to JP Morgan")
    jp_morgan['authcrypted_general_kyc_cred'] = general_auditor['authcrypted_general_kyc_cred']

    print("========================================")

    print("Financial Auditor -> Decrypt Financial KYC Credential Request from JP Morgan")
    (financial_auditor['jp_morgan_key_for_financial_auditor'], financial_auditor['financial_kyc_cred_request'], _) = await auth_decrypt(financial_auditor['wallet'],
                                                                                                                                        financial_auditor['key_for_jp_morgan'],
                                                                                                                                        financial_auditor['authcrypted_financial_kyc_cred_request'])

    print("Financial Auditor -> Create Financial KYC Credential for JP Morgan")
    financial_auditor['jp_morgan_financial_kyc_cred_values'] = json.dumps({
        "taxCountry": {"raw": "U.S.A.", "encoded": "30313233343536373839"},
        "industryClassificationCode": {"raw": "3452", "encoded": "3452"},
        "liquidity": {"raw": "2.8", "encoded": "2.8"},
        "exposureCap": {"raw": "0.5", "encoded": "0.5"},
        "creditRating": {"raw": "4", "encoded": "4"}
    })
    (financial_auditor['financial_kyc_cred'], _, _) = await anoncreds.issuer_create_credential(financial_auditor['wallet'],
                                                                                               financial_auditor['financial_kyc_cred_offer'],
                                                                                               financial_auditor['financial_kyc_cred_request'],
                                                                                               financial_auditor['jp_morgan_financial_kyc_cred_values'],
                                                                                               None,
                                                                                               None)

    print("Financial Auditor -> Encrypt Financial KYC Credential for JP Morgan")
    financial_auditor['authcrypted_financial_kyc_cred'] = await crypto.auth_crypt(financial_auditor['wallet'],
                                                                                  financial_auditor['key_for_jp_morgan'],
                                                                                  financial_auditor['jp_morgan_key_for_financial_auditor'],
                                                                                  financial_auditor['financial_kyc_cred'].encode('utf-8'))

    print("Financial Auditor -> Send encrypted Financial KYC Credential to JP Morgan")
    jp_morgan['authcrypted_financial_kyc_cred'] = financial_auditor['authcrypted_financial_kyc_cred']

    print("========================================")

    print("JP Morgan -> Decrypt General KYC Credential from General Auditor")
    (_, jp_morgan['general_kyc_cred'], _) = await auth_decrypt(jp_morgan['wallet'],
                                                               jp_morgan['key_for_general_auditor'],
                                                               jp_morgan['authcrypted_general_kyc_cred'])

    print("JP Morgan -> Get General KYC Credential Definition from Ledger")
    (_, jp_morgan['general_kyc_cred_def']) = await get_cred_def(jp_morgan['pool'],
                                                                jp_morgan['did_for_general_auditor'],
                                                                jp_morgan['general_kyc_cred_def_id'])

    print("JP Morgan -> Store General KYC Credential in Wallet")
    await anoncreds.prover_store_credential(jp_morgan['wallet'],
                                            None,
                                            jp_morgan['general_kyc_cred_request_metadata'],
                                            jp_morgan['general_kyc_cred'],
                                            jp_morgan['general_kyc_cred_def'],
                                            None)

    print("JP Morgan -> Decrypt Financial KYC Credential from Financial Auditor")
    (_, jp_morgan['financial_kyc_cred'], _) = await auth_decrypt(jp_morgan['wallet'],
                                                                 jp_morgan['key_for_financial_auditor'],
                                                                 jp_morgan['authcrypted_financial_kyc_cred'])

    print("JP Morgan -> Get Financial KYC Credential Definition from Ledger")
    (_, jp_morgan['financial_kyc_cred_def']) = await get_cred_def(jp_morgan['pool'],
                                                                  jp_morgan['did_for_financial_auditor'],
                                                                  jp_morgan['financial_kyc_cred_def_id'])

    print("JP Morgan -> Store Financial KYC Credential in Wallet")
    await anoncreds.prover_store_credential(jp_morgan['wallet'],
                                            None,
                                            jp_morgan['financial_kyc_cred_request_metadata'],
                                            jp_morgan['financial_kyc_cred'],
                                            jp_morgan['financial_kyc_cred_def'],
                                            None)

    print("========================================")

    print("Goldman Sachs -> Establish p2p connection with JP Morgan")
    (goldman_sachs['did_for_jp_morgan'],
     goldman_sachs['key_for_jp_morgan'],
     jp_morgan['did_for_goldman_sachs'],
     jp_morgan['key_for_goldman_sachs'],
     goldman_sachs['jp_morgan_connection_response']) = await onboarding(goldman_sachs, jp_morgan)

    print("Goldman Sachs -> Get JP Morgan\'s key")
    goldman_sachs['jp_morgan_key_for_goldman_sachs'] = await did.key_for_did(goldman_sachs['pool'],
                                                                             goldman_sachs['wallet'],
                                                                             goldman_sachs['jp_morgan_connection_response']['did'])

    print("Goldman Sachs -> Create General KYC Credential Proof Request")
    nonce1 = await anoncreds.generate_nonce()
    goldman_sachs['general_kyc_cred_proof_request'] = json.dumps({
        'nonce': nonce1,
        'name': 'General KYC Credential',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'id',
                'restrictions': [{'cred_def_id': general_auditor['general_kyc_cred_def_id']}]
            },
            'attr2_referent': {
                'name': 'legalName',
                'restrictions': [{'cred_def_id': general_auditor['general_kyc_cred_def_id']}]
            },
            'attr3_referent': {
                'name': 'legalOwner',
                'restrictions': [{'cred_def_id': general_auditor['general_kyc_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'primarySicCode',
                'restrictions': [{'cred_def_id': general_auditor['general_kyc_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'address',
                'restrictions': [{'cred_def_id': general_auditor['general_kyc_cred_def_id']}]
            }
        },
        'requested_predicates': {}
    })

    print("Goldman Sachs -> Encrypt General KYC Credential Proof Request with JP Morgan\'s key")
    goldman_sachs['authcrypted_general_kyc_cred_proof_request'] = await crypto.auth_crypt(goldman_sachs['wallet'],
                                                                                          goldman_sachs['key_for_jp_morgan'],
                                                                                          goldman_sachs['jp_morgan_key_for_goldman_sachs'],
                                                                                          goldman_sachs['general_kyc_cred_proof_request'].encode('utf-8'))

    print("Goldman Sachs -> Send encrypted General KYC Credential Proof Request to JP Morgan")
    jp_morgan['authcrypted_general_kyc_cred_proof_request'] = goldman_sachs['authcrypted_general_kyc_cred_proof_request']

    print("Goldman Sachs -> Create Financial KYC Credential Proof Request")
    nonce2 = await anoncreds.generate_nonce()
    goldman_sachs['financial_kyc_cred_proof_request'] = json.dumps({
        'nonce': nonce2,
        'name': 'Financial KYC Credential',
        'version': '0.1',
        'requested_attributes': {
            'attr6_referent': {
                'name': 'taxCountry',
                'restrictions': [{'cred_def_id': financial_auditor['financial_kyc_cred_def_id']}]
            },
            'attr7_referent': {
                'name': 'industryClassificationCode',
                'restrictions': [{'cred_def_id': financial_auditor['financial_kyc_cred_def_id']}]
            },
            'attr8_referent': {
                'name': 'liquidity',
                'restrictions': [{'cred_def_id': financial_auditor['financial_kyc_cred_def_id']}]
            },
            'attr9_referent': {
                'name': 'exposureCap',
                'restrictions': [{'cred_def_id': financial_auditor['financial_kyc_cred_def_id']}]
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'creditRating',
                'p_type': '>=',
                'p_value': 3,
                'restrictions': [{'cred_def_id': financial_auditor['financial_kyc_cred_def_id']}]
            }
        }
    })

    print("Goldman Sachs -> Encrypt Financial KYC Credential Proof Request with JP Morgan\'s key")
    goldman_sachs['authcrypted_financial_kyc_cred_proof_request'] = await crypto.auth_crypt(goldman_sachs['wallet'],
                                                                                            goldman_sachs['key_for_jp_morgan'],
                                                                                            goldman_sachs['jp_morgan_key_for_goldman_sachs'],
                                                                                            goldman_sachs['financial_kyc_cred_proof_request'].encode('utf-8'))

    print("Goldman Sachs -> Send encrypted Financial KYC Credential Proof Request to JP Morgan")
    jp_morgan['authcrypted_financial_kyc_cred_proof_request'] = goldman_sachs['authcrypted_financial_kyc_cred_proof_request']

    print("========================================")

    print("JP Morgan -> Decrypt General KYC Credential Proof Request from Goldman Sachs")
    (jp_morgan['goldman_sachs_key_for_jp_morgan'], jp_morgan['general_kyc_cred_proof_request'], _) = await auth_decrypt(jp_morgan['wallet'],
                                                                                                                        jp_morgan['key_for_goldman_sachs'],
                                                                                                                        jp_morgan['authcrypted_general_kyc_cred_proof_request'])

    print("JP Morgan -> Get credentials for General KYC Credential Proof Request")
    search_for_general_kyc_cred_proof_request = await anoncreds.prover_search_credentials_for_proof_req(jp_morgan['wallet'],
                                                                                                        jp_morgan['general_kyc_cred_proof_request'],
                                                                                                        None)
    cred_for_attr1 = await get_credential_for_referent(search_for_general_kyc_cred_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_general_kyc_cred_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_general_kyc_cred_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_general_kyc_cred_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_general_kyc_cred_proof_request, 'attr5_referent')
    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_general_kyc_cred_proof_request)
    jp_morgan['creds_for_general_kyc_cred_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                     cred_for_attr2['referent']: cred_for_attr2,
                                                     cred_for_attr3['referent']: cred_for_attr3,
                                                     cred_for_attr4['referent']: cred_for_attr4,
                                                     cred_for_attr5['referent']: cred_for_attr5}
    (jp_morgan['general_kyc_schemas'],
     jp_morgan['general_kyc_cred_defs'],
     jp_morgan['general_kyc_revoc_states']) = await prover_get_entities_from_ledger(jp_morgan['pool'],
                                                                                    jp_morgan['did_for_goldman_sachs'],
                                                                                    jp_morgan['creds_for_general_kyc_cred_proof'])

    print("JP Morgan -> Create General KYC Credential Proof")
    jp_morgan['general_kyc_cred_requested_creds'] = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
                                 'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
                                 'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
                                 'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
                                 'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True}},
        'requested_predicates': {}
    })
    jp_morgan['general_kyc_cred_proof'] = await anoncreds.prover_create_proof(jp_morgan['wallet'],
                                                                              jp_morgan['general_kyc_cred_proof_request'],
                                                                              jp_morgan['general_kyc_cred_requested_creds'],
                                                                              jp_morgan['master_secret_id'],
                                                                              jp_morgan['general_kyc_schemas'],
                                                                              jp_morgan['general_kyc_cred_defs'],
                                                                              jp_morgan['general_kyc_revoc_states'])

    print("JP Morgan -> Encrypt General KYC Credential Proof for Goldman Sachs")
    jp_morgan['authcrypted_general_kyc_cred_proof'] = await crypto.auth_crypt(jp_morgan['wallet'],
                                                                              jp_morgan['key_for_goldman_sachs'],
                                                                              jp_morgan['goldman_sachs_key_for_jp_morgan'],
                                                                              jp_morgan['general_kyc_cred_proof'].encode('utf-8'))

    print("JP Morgan -> Send encrypted General KYC Credential Proof to Goldman Sachs")
    goldman_sachs['authcrypted_general_kyc_cred_proof'] = jp_morgan['authcrypted_general_kyc_cred_proof']

    print("JP Morgan -> Decrypt Financial KYC Credential Proof Request from Goldman Sachs")
    (jp_morgan['goldman_sachs_key_for_jp_morgan'], jp_morgan['financial_kyc_cred_proof_request'], _) = await auth_decrypt(jp_morgan['wallet'],
                                                                                                                          jp_morgan['key_for_goldman_sachs'],
                                                                                                                          jp_morgan['authcrypted_financial_kyc_cred_proof_request'])

    print("JP Morgan -> Get credentials for Financial KYC Credential Proof Request")
    search_for_financial_kyc_cred_proof_request = await anoncreds.prover_search_credentials_for_proof_req(jp_morgan['wallet'],
                                                                                                          jp_morgan['financial_kyc_cred_proof_request'],
                                                                                                          None)
    cred_for_attr6 = await get_credential_for_referent(search_for_financial_kyc_cred_proof_request, 'attr6_referent')
    cred_for_attr7 = await get_credential_for_referent(search_for_financial_kyc_cred_proof_request, 'attr7_referent')
    cred_for_attr8 = await get_credential_for_referent(search_for_financial_kyc_cred_proof_request, 'attr8_referent')
    cred_for_attr9 = await get_credential_for_referent(search_for_financial_kyc_cred_proof_request, 'attr9_referent')
    cred_for_predicate1 = await get_credential_for_referent(search_for_financial_kyc_cred_proof_request, 'predicate1_referent')
    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_financial_kyc_cred_proof_request)
    jp_morgan['creds_for_financial_kyc_cred_proof'] = {cred_for_attr6['referent']: cred_for_attr6,
                                                       cred_for_attr7['referent']: cred_for_attr7,
                                                       cred_for_attr8['referent']: cred_for_attr8,
                                                       cred_for_attr9['referent']: cred_for_attr9,
                                                       cred_for_predicate1['referent']: cred_for_predicate1}
    (jp_morgan['financial_kyc_schemas'],
     jp_morgan['financial_kyc_cred_defs'],
     jp_morgan['financial_kyc_revoc_states']) = await prover_get_entities_from_ledger(jp_morgan['pool'],
                                                                                      jp_morgan['did_for_goldman_sachs'],
                                                                                      jp_morgan['creds_for_financial_kyc_cred_proof'])

    print("JP Morgan -> Create Financial KYC Credential Proof")
    jp_morgan['financial_kyc_cred_requested_creds'] = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {'attr6_referent': {'cred_id': cred_for_attr6['referent'], 'revealed': True},
                                 'attr7_referent': {'cred_id': cred_for_attr7['referent'], 'revealed': True},
                                 'attr8_referent': {'cred_id': cred_for_attr8['referent'], 'revealed': True},
                                 'attr9_referent': {'cred_id': cred_for_attr9['referent'], 'revealed': True}},
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })
    jp_morgan['financial_kyc_cred_proof'] = await anoncreds.prover_create_proof(jp_morgan['wallet'],
                                                                                jp_morgan['financial_kyc_cred_proof_request'],
                                                                                jp_morgan['financial_kyc_cred_requested_creds'],
                                                                                jp_morgan['master_secret_id'],
                                                                                jp_morgan['financial_kyc_schemas'],
                                                                                jp_morgan['financial_kyc_cred_defs'],
                                                                                jp_morgan['financial_kyc_revoc_states'])

    print("JP Morgan -> Encrypt Financial KYC Credential Proof for Goldman Sachs")
    jp_morgan['authcrypted_financial_kyc_cred_proof'] = await crypto.auth_crypt(jp_morgan['wallet'],
                                                                                jp_morgan['key_for_goldman_sachs'],
                                                                                jp_morgan['goldman_sachs_key_for_jp_morgan'],
                                                                                jp_morgan['financial_kyc_cred_proof'].encode('utf-8'))

    print("JP Morgan -> Send encrypted Financial KYC Credential Proof to Goldman Sachs")
    goldman_sachs['authcrypted_financial_kyc_cred_proof'] = jp_morgan['authcrypted_financial_kyc_cred_proof']

    print("========================================")

    print("Goldman Sachs -> Decrypt General KYC Credential Proof from JP Morgan")
    (_, goldman_sachs['general_kyc_cred_proof'], decrypted_general_kyc_cred_proof) = await auth_decrypt(goldman_sachs['wallet'],
                                                                                                        goldman_sachs['key_for_jp_morgan'],
                                                                                                        goldman_sachs['authcrypted_general_kyc_cred_proof'])
    (goldman_sachs['general_kyc_schemas'],
     goldman_sachs['general_kyc_cred_defs'],
     goldman_sachs['general_kyc_revoc_ref_defs'],
     goldman_sachs['general_kyc_revoc_regs']) = await verifier_get_entities_from_ledger(goldman_sachs['pool'],
                                                                                        goldman_sachs['did'],
                                                                                        decrypted_general_kyc_cred_proof['identifiers'])

    print("Goldman Sachs -> Verify General KYC Credential Proof from JP Morgan")
    assert '101' == decrypted_general_kyc_cred_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
    assert 'JP Morgan Coop.' == decrypted_general_kyc_cred_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
    assert 'Mr. Morgan' == decrypted_general_kyc_cred_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert '1102' == decrypted_general_kyc_cred_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '207A, Mulberry Woods, New York' == decrypted_general_kyc_cred_proof['requested_proof']['revealed_attrs']['attr5_referent']['raw']
    assert await anoncreds.verifier_verify_proof(goldman_sachs['general_kyc_cred_proof_request'],
                                                 goldman_sachs['general_kyc_cred_proof'],
                                                 goldman_sachs['general_kyc_schemas'],
                                                 goldman_sachs['general_kyc_cred_defs'],
                                                 goldman_sachs['general_kyc_revoc_ref_defs'],
                                                 goldman_sachs['general_kyc_revoc_regs'])

    print("Goldman Sachs -> Decrypt Financial KYC Credential Proof from JP Morgan")
    (_, goldman_sachs['financial_kyc_cred_proof'], decrypted_financial_kyc_cred_proof) = await auth_decrypt(goldman_sachs['wallet'],
                                                                                                            goldman_sachs['key_for_jp_morgan'],
                                                                                                            goldman_sachs['authcrypted_financial_kyc_cred_proof'])
    (goldman_sachs['financial_kyc_schemas'],
     goldman_sachs['financial_kyc_cred_defs'],
     goldman_sachs['financial_kyc_revoc_ref_defs'],
     goldman_sachs['financial_kyc_revoc_regs']) = await verifier_get_entities_from_ledger(goldman_sachs['pool'],
                                                                                          goldman_sachs['did'],
                                                                                          decrypted_financial_kyc_cred_proof['identifiers'])

    print("Goldman Sachs -> Verify Financial KYC Credential Proof from JP Morgan")
    assert 'U.S.A.' == decrypted_financial_kyc_cred_proof['requested_proof']['revealed_attrs']['attr6_referent']['raw']
    assert '3452' == decrypted_financial_kyc_cred_proof['requested_proof']['revealed_attrs']['attr7_referent']['raw']
    assert '2.8' == decrypted_financial_kyc_cred_proof['requested_proof']['revealed_attrs']['attr8_referent']['raw']
    assert '0.5' == decrypted_financial_kyc_cred_proof['requested_proof']['revealed_attrs']['attr9_referent']['raw']
    assert await anoncreds.verifier_verify_proof(goldman_sachs['financial_kyc_cred_proof_request'],
                                                 goldman_sachs['financial_kyc_cred_proof'],
                                                 goldman_sachs['financial_kyc_schemas'],
                                                 goldman_sachs['financial_kyc_cred_defs'],
                                                 goldman_sachs['financial_kyc_revoc_ref_defs'],
                                                 goldman_sachs['financial_kyc_revoc_regs'])

    print("========================================")

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

    print("Close and Delete JP Morgan\'s Wallet")
    await wallet.close_wallet(jp_morgan['wallet'])
    await wallet.delete_wallet(jp_morgan['wallet_config'], jp_morgan['wallet_credentials'])

    print("Close and Delete Pool")
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    print("========================================")
    print("=============== End Demo ===============")
    print("========================================")


async def onboarding(_from, _to):

    print(tab + "====================================")

    print(tab + _from['name'] + ' -> Create pairwise did and key for ' + _to['name'] + ' and store in wallet')
    (from_to_did, from_to_key) = await did.create_and_store_my_did(_from['wallet'], "{}")

    print(tab + _from['name'] + ' -> Send the pairwise did and key to ledger')
    await send_nym(_from['pool'], _from['wallet'], _from['did'], from_to_did, from_to_key, None)

    print(tab + _from['name'] + ' -> Create connection request for ' + _to['name'] + ' with the pairwise did and a nonce')
    _from['connection_request'] = {'did': from_to_did,
                                   'nonce': 123456789}

    print(tab + _from['name'] + ' -> Send connection request to ' + _to['name'])
    _to['connection_request'] = _from['connection_request']

    print(tab + "====================================")

    print(tab + _to['name'] + ' -> Create wallet')
    if 'wallet' not in _to:
        try:
            await wallet.create_wallet(_to['wallet_config'], _to['wallet_credentials'])
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass
        _to['wallet'] = await wallet.open_wallet(_to['wallet_config'], _to['wallet_credentials'])

    print(tab + _to['name'] + ' -> Create pairwise did and key for ' + _from['name'] + ' and store in wallet')
    (to_from_did, to_from_key) = await did.create_and_store_my_did(_to['wallet'], "{}")

    print(tab + _to['name'] + ' -> Create connection response for ' + _from['name'] + ' with the pairwise did and key and the nonce')
    _to['connection_response'] = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': _to['connection_request']['nonce']
    })

    print(tab + _to['name'] + ' -> Get ' + _from['name']  + '\'s pairwise key from ledger')
    from_to_verkey = await did.key_for_did(_from['pool'], _to['wallet'], _to['connection_request']['did'])

    print(tab + _to['name'] + ' -> Encrypt connection response with '  + _from['name']  + '\'s pairwise key')
    _to['anoncrypted_connection_response'] = await crypto.anon_crypt(from_to_verkey, _to['connection_response'].encode('utf-8'))

    print(tab + _to['name'] + ' -> Send connection response to ' + _from['name'])
    _from['anoncrypted_connection_response'] = _to['anoncrypted_connection_response']

    print(tab + "====================================")

    print(tab + _from['name'] + ' -> Decrypt connection response from ' + _to['name'])
    _from['connection_response'] = json.loads((await crypto.anon_decrypt(_from['wallet'],
                                                                         from_to_key,
                                                                         _from['anoncrypted_connection_response'])).decode("utf-8"))

    print(tab + _from['name'] + ' -> Get nonce from response and validate with original nonce')
    assert _from['connection_request']['nonce'] == _from['connection_response']['nonce']

    print(tab + _from['name'] + ' -> Send ' + _to['name'] + '\'s pairwise did and key to ledger')
    await send_nym(_from['pool'], _from['wallet'], _from['did'], to_from_did, to_from_key, None)

    print(tab + "====================================")

    return (from_to_did, from_to_key, to_from_did, to_from_key, _from['connection_response'])


async def get_verinym(_from, _to):

    name = _to['name']
    from_to_key = _from['key_for_' + name]
    to_from_did = _to['did_for_government']
    to_from_key = _to['key_for_government']

    print(tab + _to['name'] + ' -> Create did and key and store in wallet')
    (to_did, to_key) = await did.create_and_store_my_did(_to['wallet'], "{}")

    print(tab + _to['name'] + ' -> Create message info with the did and key')
    _to['did_info'] = json.dumps({'did': to_did,
                                  'verkey': to_key})

    print(tab + _to['name'] + ' -> Encrypt the message and it\'s own pairwise key with ' + _from['name'] + '\'s pairwise key ')
    _to['authcrypted_did_info'] = await crypto.auth_crypt(_to['wallet'], to_from_key, from_to_key, _to['did_info'].encode('utf-8'))

    print(tab + _to['name'] + ' -> Send encrypted message to ' + _from['name'])
    _from['authcrypted_did_info'] = _to['authcrypted_did_info']

    print(tab + "====================================")

    print(tab + _from['name'] + ' -> Decrypt message from ' + _to['name'])
    (sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info) = await auth_decrypt(_from['wallet'],
                                                                                              from_to_key,
                                                                                              _from['authcrypted_did_info'])
    print(tab + _from['name'] + ' -> Get ' + _to['name'] + '\'s pairwise key from ledger and validate with sender\'s pairwise key in decrypted message')
    assert sender_verkey == await did.key_for_did(_from['pool'], _from['wallet'], to_from_did)

    print(tab + _from['name'] + ' -> Send ' + _to['name'] + '\'s did and key to ledger')
    await send_nym(_from['pool'], _from['wallet'], _from['did'], authdecrypted_did_info['did'], authdecrypted_did_info['verkey'], _to['role'])

    print(tab + "====================================")

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
