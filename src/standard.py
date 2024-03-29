import asyncio
import time
from indy import anoncreds, crypto, did, ledger, pool, wallet

import json
from typing import Optional


async def run():
    print("Getting started -> started")

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(2)

    pool_ = {
        'name': 'pool1',
        'config': json.dumps({"genesis_txn": '/home/indy/sandbox/pool_transactions_genesis'})
    }
    print("Open Pool Ledger: {}".format(pool_['name']))

    try:
        await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print("==============================")
    print("=== Getting Trust Anchor credentials for Faber, Acme, Thrift and Government  ==")
    print("------------------------------")

    print("\"Sovrin Steward\" -> Create wallet")
    steward = {
        'name': "Sovrin Steward",
        'wallet_config': json.dumps({'id': 'sovrin_steward_wallet'}),
        'wallet_credentials': json.dumps({'key': 'steward_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }

    try:
        await wallet.create_wallet(steward['wallet_config'], steward['wallet_credentials'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass

    steward['wallet'] = await wallet.open_wallet(steward['wallet_config'], steward['wallet_credentials'])

    print("\"Sovrin Steward\" -> Create and store in Wallet DID from seed")
    steward['did_info'] = json.dumps({'seed': steward['seed']})
    steward['did'], steward['key'] = await did.create_and_store_my_did(steward['wallet'], steward['did_info'])

    print("==============================")
    print("== Getting Trust Anchor credentials - Government Onboarding  ==")
    print("------------------------------")

    government = {
        'name': 'Government',
        'wallet_config': json.dumps({'id': 'government_wallet'}),
        'wallet_credentials': json.dumps({'key': 'government_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_government'], steward['key_for_government'], government['did_for_steward'], \
    government['key_for_steward'], _ = await onboarding(steward, government)

    print("==============================")
    print("== Getting Trust Anchor credentials - Government getting Verinym  ==")
    print("------------------------------")

    government['did'] = await get_verinym(steward, steward['did_for_government'], steward['key_for_government'],
                                          government, government['did_for_steward'], government['key_for_steward'])

    print("==============================")
    print("== Getting Trust Anchor credentials - Faber Onboarding  ==")
    print("------------------------------")

    faber = {
        'name': 'Faber',
        'wallet_config': json.dumps({'id': 'faber_wallet'}),
        'wallet_credentials': json.dumps({'key': 'faber_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_faber'], steward['key_for_faber'], faber['did_for_steward'], faber['key_for_steward'], _ = \
        await onboarding(steward, faber)

    print("==============================")
    print("== Getting Trust Anchor credentials - Faber getting Verinym  ==")
    print("------------------------------")

    faber['did'] = \
        await get_verinym(steward, steward['did_for_faber'], steward['key_for_faber'],
                          faber, faber['did_for_steward'], faber['key_for_steward'])

    print("==============================")
    print("== Getting Trust Anchor credentials - Acme Onboarding  ==")
    print("------------------------------")

    acme = {
        'name': 'Acme',
        'wallet_config': json.dumps({'id': 'acme_wallet'}),
        'wallet_credentials': json.dumps({'key': 'acme_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_acme'], steward['key_for_acme'], acme['did_for_steward'], acme['key_for_steward'], _ = \
        await onboarding(steward, acme)

    print("==============================")
    print("== Getting Trust Anchor credentials - Acme getting Verinym  ==")
    print("------------------------------")

    acme['did'] = await get_verinym(steward, steward['did_for_acme'], steward['key_for_acme'],
                                    acme, acme['did_for_steward'], acme['key_for_steward'])

    print("==============================")
    print("== Getting Trust Anchor credentials - Thrift Onboarding  ==")
    print("------------------------------")

    thrift = {
        'name': 'Thrift',
        'wallet_config': json.dumps({'id': 'thrift_wallet'}),
        'wallet_credentials': json.dumps({'key': 'thrift_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_thrift'], steward['key_for_thrift'], thrift['did_for_steward'], thrift['key_for_steward'], _ = \
        await onboarding(steward, thrift)

    print("==============================")
    print("== Getting Trust Anchor credentials - Thrift getting Verinym  ==")
    print("------------------------------")

    thrift['did'] = await get_verinym(steward, steward['did_for_thrift'], steward['key_for_thrift'],
                                      thrift, thrift['did_for_steward'], thrift['key_for_steward'])

    print("==============================")
    print("=== Credential Schemas Setup ==")
    print("------------------------------")

    print("\"Government\" -> Create \"Job-Certificate\" Schema")
    job_certificate = {
        'name': 'Job-Certificate',
        'version': '0.2',
        'attributes': ['first_name', 'last_name', 'salary', 'employee_status', 'experience']
    }
    (government['job_certificate_schema_id'], government['job_certificate_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], job_certificate['name'], job_certificate['version'],
                                             json.dumps(job_certificate['attributes']))
    job_certificate_schema_id = government['job_certificate_schema_id']

    print("\"Government\" -> Send \"Job-Certificate\" Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['job_certificate_schema'])

    print("\"Government\" -> Create \"Transcript\" Schema")
    transcript = {
        'name': 'Transcript',
        'version': '1.2',
        'attributes': ['first_name', 'last_name', 'degree', 'status', 'year', 'average', 'ssn']
    }
    (government['transcript_schema_id'], government['transcript_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], transcript['name'], transcript['version'],
                                             json.dumps(transcript['attributes']))
    transcript_schema_id = government['transcript_schema_id']

    print("\"Government\" -> Send \"Transcript\" Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['transcript_schema'])

    time.sleep(1)  # sleep 1 second before getting schema

    print("==============================")
    print("=== Faber Credential Definition Setup ==")
    print("------------------------------")

    print("\"Faber\" -> Get \"Transcript\" Schema from Ledger")
    (faber['transcript_schema_id'], faber['transcript_schema']) = \
        await get_schema(faber['pool'], faber['did'], transcript_schema_id)

    print("\"Faber\" -> Create and store in Wallet \"Faber Transcript\" Credential Definition")
    transcript_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (faber['transcript_cred_def_id'], faber['transcript_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(faber['wallet'], faber['did'],
                                                               faber['transcript_schema'], transcript_cred_def['tag'],
                                                               transcript_cred_def['type'],
                                                               json.dumps(transcript_cred_def['config']))

    print("\"Faber\" -> Send  \"Faber Transcript\" Credential Definition to Ledger")
    await send_cred_def(faber['pool'], faber['wallet'], faber['did'], faber['transcript_cred_def'])

    print("==============================")
    print("=== Acme Credential Definition Setup ==")
    print("------------------------------")

    print("\"Acme\" -> Get from Ledger \"Job-Certificate\" Schema")
    (acme['job_certificate_schema_id'], acme['job_certificate_schema']) = \
        await get_schema(acme['pool'], acme['did'], job_certificate_schema_id)

    print("\"Acme\" -> Create and store in Wallet \"Acme Job-Certificate\" Credential Definition")
    job_certificate_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (acme['job_certificate_cred_def_id'], acme['job_certificate_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(acme['wallet'], acme['did'],
                                                               acme['job_certificate_schema'],
                                                               job_certificate_cred_def['tag'],
                                                               job_certificate_cred_def['type'],
                                                               json.dumps(job_certificate_cred_def['config']))

    print("\"Acme\" -> Send \"Acme Job-Certificate\" Credential Definition to Ledger")
    await send_cred_def(acme['pool'], acme['wallet'], acme['did'], acme['job_certificate_cred_def'])

    print("==============================")
    print("=== Getting Transcript with Faber ==")
    print("==============================")
    print("== Getting Transcript with Faber - Onboarding ==")
    print("------------------------------")

    alice = {
        'name': 'Alice',
        'wallet_config': json.dumps({'id': 'alice_wallet'}),
        'wallet_credentials': json.dumps({'key': 'alice_wallet_key'}),
        'pool': pool_['handle'],
    }
    faber['did_for_alice'], faber['key_for_alice'], alice['did_for_faber'], alice['key_for_faber'], \
    faber['alice_connection_response'] = await onboarding(faber, alice)

    print("==============================")
    print("== Getting Transcript with Faber - Getting Transcript Credential ==")
    print("------------------------------")

    print("\"Faber\" -> Create \"Transcript\" Credential Offer for Alice")
    faber['transcript_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(faber['wallet'], faber['transcript_cred_def_id'])

    print("\"Faber\" -> Get key for Alice did")
    faber['alic_key_for_faber'] = \
        await did.key_for_did(faber['pool'], faber['wallet'], faber['alice_connection_response']['did'])

    print("\"Faber\" -> Authcrypt \"Transcript\" Credential Offer for Alice")
    faber['authcrypted_transcript_cred_offer'] = \
        await crypto.auth_crypt(faber['wallet'], faber['key_for_alice'], faber['alic_key_for_faber'],
                                faber['transcript_cred_offer'].encode('utf-8'))

    print("\"Faber\" -> Send authcrypted \"Transcript\" Credential Offer to Alice")
    alice['authcrypted_transcript_cred_offer'] = faber['authcrypted_transcript_cred_offer']

    print("\"Alice\" -> Authdecrypted \"Transcript\" Credential Offer from Faber")
    alice['faber_key_for_alice'], alice['transcript_cred_offer'], authdecrypted_transcript_cred_offer = \
        await auth_decrypt(alice['wallet'], alice['key_for_faber'], alice['authcrypted_transcript_cred_offer'])
    alice['transcript_schema_id'] = authdecrypted_transcript_cred_offer['schema_id']
    alice['transcript_cred_def_id'] = authdecrypted_transcript_cred_offer['cred_def_id']

    print("\"Alice\" -> Create and store \"Alice\" Master Secret in Wallet")
    alice['master_secret_id'] = await anoncreds.prover_create_master_secret(alice['wallet'], None)

    print("\"Alice\" -> Get \"Faber Transcript\" Credential Definition from Ledger")
    (alice['faber_transcript_cred_def_id'], alice['faber_transcript_cred_def']) = \
        await get_cred_def(alice['pool'], alice['did_for_faber'], authdecrypted_transcript_cred_offer['cred_def_id'])

    print("\"Alice\" -> Create \"Transcript\" Credential Request for Faber")
    (alice['transcript_cred_request'], alice['transcript_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(alice['wallet'], alice['did_for_faber'],
                                                     alice['transcript_cred_offer'], alice['faber_transcript_cred_def'],
                                                     alice['master_secret_id'])

    print("\"Alice\" -> Authcrypt \"Transcript\" Credential Request for Faber")
    alice['authcrypted_transcript_cred_request'] = \
        await crypto.auth_crypt(alice['wallet'], alice['key_for_faber'], alice['faber_key_for_alice'],
                                alice['transcript_cred_request'].encode('utf-8'))

    print("\"Alice\" -> Send authcrypted \"Transcript\" Credential Request to Faber")
    alice['transcript_cred_values'] = json.dumps({
        "first_name": {"raw": "Alice", "encoded": "1139481716457488690172217916278103335"},
        "last_name": {"raw": "Garcia", "encoded": "5321642780241790123587902456789123452"},
        "degree": {"raw": "Bachelor of Science, Marketing", "encoded": "12434523576212321"},
        "status": {"raw": "graduated", "encoded": "2213454313412354"},
        "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
        "year": {"raw": "2015", "encoded": "2015"},
        "average": {"raw": "5", "encoded": "5"}
    })
    faber['authcrypted_transcript_cred_request'] = alice['authcrypted_transcript_cred_request']
    faber['alice_transcript_cred_values'] = alice['transcript_cred_values']

    print("\"Faber\" -> Authdecrypt \"Transcript\" Credential Request from Alice")
    faber['alice_key_for_faber'], faber['transcript_cred_request'], _ = \
        await auth_decrypt(faber['wallet'], faber['key_for_alice'], faber['authcrypted_transcript_cred_request'])

    print("\"Faber\" -> Create \"Transcript\" Credential for Alice")

    faber['transcript_cred'], _, _ = \
        await anoncreds.issuer_create_credential(faber['wallet'], faber['transcript_cred_offer'],
                                                 faber['transcript_cred_request'],
                                                 faber['alice_transcript_cred_values'], None, None)

    print("\"Faber\" -> Authcrypt \"Transcript\" Credential for Alice")
    faber['authcrypted_transcript_cred'] = \
        await crypto.auth_crypt(faber['wallet'], faber['key_for_alice'], faber['alice_key_for_faber'],
                                faber['transcript_cred'].encode('utf-8'))

    print("\"Faber\" -> Send authcrypted \"Transcript\" Credential to Alice")
    alice['authcrypted_transcript_cred'] = faber['authcrypted_transcript_cred']

    print("\"Alice\" -> Authdecrypted \"Transcript\" Credential from Faber")
    _, alice['transcript_cred'], _ = \
        await auth_decrypt(alice['wallet'], alice['key_for_faber'], alice['authcrypted_transcript_cred'])

    print("\"Alice\" -> Store \"Transcript\" Credential from Faber")
    _, alice['transcript_cred_def'] = await get_cred_def(alice['pool'], alice['did_for_faber'],
                                                         alice['transcript_cred_def_id'])

    await anoncreds.prover_store_credential(alice['wallet'], None, alice['transcript_cred_request_metadata'],
                                            alice['transcript_cred'], alice['transcript_cred_def'], None)

    print("==============================")
    print("=== Apply for the job with Acme ==")
    print("==============================")
    print("== Apply for the job with Acme - Onboarding ==")
    print("------------------------------")

    acme['did_for_alice'], acme['key_for_alice'], alice['did_for_acme'], alice['key_for_acme'], \
    acme['alice_connection_response'] = await onboarding(acme, alice)

    print("==============================")
    print("== Apply for the job with Acme - Transcript proving ==")
    print("------------------------------")

    print("\"Acme\" -> Create \"Job-Application\" Proof Request")
    nonce = await anoncreds.generate_nonce()
    acme['job_application_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'Job-Application',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name'
            },
            'attr2_referent': {
                'name': 'last_name'
            },
            'attr3_referent': {
                'name': 'degree',
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'ssn',
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            },
            'attr6_referent': {
                'name': 'phone_number'
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'average',
                'p_type': '>=',
                'p_value': 4,
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            }
        }
    })

    print("\"Acme\" -> Get key for Alice did")
    acme['alice_key_for_acme'] = \
        await did.key_for_did(acme['pool'], acme['wallet'], acme['alice_connection_response']['did'])

    print("\"Acme\" -> Authcrypt \"Job-Application\" Proof Request for Alice")
    acme['authcrypted_job_application_proof_request'] = \
        await crypto.auth_crypt(acme['wallet'], acme['key_for_alice'], acme['alice_key_for_acme'],
                                acme['job_application_proof_request'].encode('utf-8'))

    print("\"Acme\" -> Send authcrypted \"Job-Application\" Proof Request to Alice")
    alice['authcrypted_job_application_proof_request'] = acme['authcrypted_job_application_proof_request']

    print("\"Alice\" -> Authdecrypt \"Job-Application\" Proof Request from Acme")
    alice['acme_key_for_alice'], alice['job_application_proof_request'], _ = \
        await auth_decrypt(alice['wallet'], alice['key_for_acme'], alice['authcrypted_job_application_proof_request'])

    print("\"Alice\" -> Get credentials for \"Job-Application\" Proof Request")

    search_for_job_application_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(alice['wallet'],
                                                                alice['job_application_proof_request'], None)

    cred_for_attr1 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr5_referent')
    cred_for_predicate1 = \
        await get_credential_for_referent(search_for_job_application_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_job_application_proof_request)

    alice['creds_for_job_application_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                cred_for_attr2['referent']: cred_for_attr2,
                                                cred_for_attr3['referent']: cred_for_attr3,
                                                cred_for_attr4['referent']: cred_for_attr4,
                                                cred_for_attr5['referent']: cred_for_attr5,
                                                cred_for_predicate1['referent']: cred_for_predicate1}

    alice['schemas'], alice['cred_defs'], alice['revoc_states'] = \
        await prover_get_entities_from_ledger(alice['pool'], alice['did_for_acme'],
                                              alice['creds_for_job_application_proof'], alice['name'])

    print("\"Alice\" -> Create \"Job-Application\" Proof")
    alice['job_application_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr1_referent': 'Alice',
            'attr2_referent': 'Garcia',
            'attr6_referent': '123-45-6789'
        },
        'requested_attributes': {
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
            'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True},
        },
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })

    alice['job_application_proof'] = \
        await anoncreds.prover_create_proof(alice['wallet'], alice['job_application_proof_request'],
                                            alice['job_application_requested_creds'], alice['master_secret_id'],
                                            alice['schemas'], alice['cred_defs'], alice['revoc_states'])

    print("\"Alice\" -> Authcrypt \"Job-Application\" Proof for Acme")
    alice['authcrypted_job_application_proof'] = \
        await crypto.auth_crypt(alice['wallet'], alice['key_for_acme'], alice['acme_key_for_alice'],
                                alice['job_application_proof'].encode('utf-8'))

    print("\"Alice\" -> Send authcrypted \"Job-Application\" Proof to Acme")
    acme['authcrypted_job_application_proof'] = alice['authcrypted_job_application_proof']

    print("\"Acme\" -> Authdecrypted \"Job-Application\" Proof from Alice")
    _, acme['job_application_proof'], decrypted_job_application_proof = \
        await auth_decrypt(acme['wallet'], acme['key_for_alice'], acme['authcrypted_job_application_proof'])

    acme['schemas'], acme['cred_defs'], acme['revoc_ref_defs'], acme['revoc_regs'] = \
        await verifier_get_entities_from_ledger(acme['pool'], acme['did'],
                                                decrypted_job_application_proof['identifiers'], acme['name'])

    print("\"Acme\" -> Verify \"Job-Application\" Proof from Alice")
    assert 'Bachelor of Science, Marketing' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert 'graduated' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '123-45-6789' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr5_referent']['raw']

    assert 'Alice' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr1_referent']
    assert 'Garcia' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr2_referent']
    assert '123-45-6789' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr6_referent']

    assert await anoncreds.verifier_verify_proof(acme['job_application_proof_request'], acme['job_application_proof'],
                                                 acme['schemas'], acme['cred_defs'], acme['revoc_ref_defs'],
                                                 acme['revoc_regs'])

    print("==============================")
    print("== Apply for the job with Acme - Getting Job-Certificate Credential ==")
    print("------------------------------")

    print("\"Acme\" -> Create \"Job-Certificate\" Credential Offer for Alice")
    acme['job_certificate_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(acme['wallet'], acme['job_certificate_cred_def_id'])

    print("\"Acme\" -> Get key for Alice did")
    acme['alice_key_for_acme'] = \
        await did.key_for_did(acme['pool'], acme['wallet'], acme['alice_connection_response']['did'])

    print("\"Acme\" -> Authcrypt \"Job-Certificate\" Credential Offer for Alice")
    acme['authcrypted_job_certificate_cred_offer'] = \
        await crypto.auth_crypt(acme['wallet'], acme['key_for_alice'], acme['alice_key_for_acme'],
                                acme['job_certificate_cred_offer'].encode('utf-8'))

    print("\"Acme\" -> Send authcrypted \"Job-Certificate\" Credential Offer to Alice")
    alice['authcrypted_job_certificate_cred_offer'] = acme['authcrypted_job_certificate_cred_offer']

    print("\"Alice\" -> Authdecrypted \"Job-Certificate\" Credential Offer from Acme")
    alice['acme_key_for_alice_alice'], alice['job_certificate_cred_offer'], job_certificate_cred_offer = \
        await auth_decrypt(alice['wallet'], alice['key_for_acme'], alice['authcrypted_job_certificate_cred_offer'])

    print("\"Alice\" -> Get \"Acme Job-Certificate\" Credential Definition from Ledger")
    (alice['acme_job_certificate_cred_def_id'], alice['acme_job_certificate_cred_def']) = \
        await get_cred_def(alice['pool'], alice['did_for_acme'], job_certificate_cred_offer['cred_def_id'])

    print("\"Alice\" -> Create and store in Wallet \"Job-Certificate\" Credential Request for Acme")
    (alice['job_certificate_cred_request'], alice['job_certificate_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(alice['wallet'], alice['did_for_acme'],
                                                     alice['job_certificate_cred_offer'],
                                                     alice['acme_job_certificate_cred_def'], alice['master_secret_id'])

    print("\"Alice\" -> Authcrypt \"Job-Certificate\" Credential Request for Acme")
    alice['authcrypted_job_certificate_cred_request'] = \
        await crypto.auth_crypt(alice['wallet'], alice['key_for_acme'], alice['acme_key_for_alice'],
                                alice['job_certificate_cred_request'].encode('utf-8'))

    print("\"Alice\" -> Send authcrypted \"Job-Certificate\" Credential Request to Acme")
    alice['job_certificate_cred_values'] = json.dumps({
        "first_name": {"raw": "Alice", "encoded": "245712572474217942457235975012103335"},
        "last_name": {"raw": "Garcia", "encoded": "312643218496194691632153761283356127"},
        "employee_status": {"raw": "Permanent", "encoded": "2143135425425143112321314321"},
        "salary": {"raw": "2400", "encoded": "2400"},
        "experience": {"raw": "10", "encoded": "10"}
    })
    acme['authcrypted_job_certificate_cred_request'] = alice['authcrypted_job_certificate_cred_request']
    acme['job_certificate_cred_values'] = alice['job_certificate_cred_values']

    print("\"Acme\" -> Authdecrypt \"Job-Certificate\" Credential Request from Alice")
    acme['alice_key_for_acme'], acme['job_certificate_cred_request'], _ = \
        await auth_decrypt(acme['wallet'], acme['key_for_alice'], acme['authcrypted_job_certificate_cred_request'])

    print("\"Acme\" -> Create \"Job-Certificate\" Credential for Alice")

    acme['job_certificate_cred'], _, _ = \
        await anoncreds.issuer_create_credential(acme['wallet'], acme['job_certificate_cred_offer'],
                                                 acme['job_certificate_cred_request'],
                                                 acme['job_certificate_cred_values'], None, None)

    print("\"Acme\" -> Authcrypt \"Job-Certificate\" Credential for Alice")
    acme['authcrypted_job_certificate_cred'] = \
        await crypto.auth_crypt(acme['wallet'], acme['key_for_alice'], acme['alice_key_for_acme'],
                                acme['job_certificate_cred'].encode('utf-8'))

    print("\"Acme\" -> Send authcrypted \"Job-Certificate\" Credential to Alice")
    alice['authcrypted_job_certificate_cred'] = acme['authcrypted_job_certificate_cred']

    print("\"Alice\" -> Authdecrypted \"Job-Certificate\" Credential from Acme")
    _, alice['job_certificate_cred'], _ = \
        await auth_decrypt(alice['wallet'], alice['key_for_acme'], alice['authcrypted_job_certificate_cred'])

    print("\"Alice\" -> Store \"Job-Certificate\" Credential")
    await anoncreds.prover_store_credential(alice['wallet'], None, alice['job_certificate_cred_request_metadata'],
                                            alice['job_certificate_cred'],
                                            alice['acme_job_certificate_cred_def'], None)

    print("==============================")
    print("=== Apply for the loan with Thrift ==")
    print("==============================")
    print("== Apply for the loan with Thrift - Onboarding ==")
    print("------------------------------")

    thrift['did_for_alice'], thrift['key_for_alice'], alice['did_for_thrift'], alice['key_for_thrift'], \
    thrift['alice_connection_response'] = await onboarding(thrift, alice)

    print("==============================")
    print("== Apply for the loan with Thrift - Job-Certificate proving  ==")
    print("------------------------------")

    print("\"Thrift\" -> Create \"Loan-Application-Basic\" Proof Request")
    nonce = await anoncreds.generate_nonce()
    thrift['apply_loan_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'Loan-Application-Basic',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'employee_status',
                'restrictions': [{'cred_def_id': acme['job_certificate_cred_def_id']}]
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'salary',
                'p_type': '>=',
                'p_value': 2000,
                'restrictions': [{'cred_def_id': acme['job_certificate_cred_def_id']}]
            },
            'predicate2_referent': {
                'name': 'experience',
                'p_type': '>=',
                'p_value': 1,
                'restrictions': [{'cred_def_id': acme['job_certificate_cred_def_id']}]
            }
        }
    })

    print("\"Thrift\" -> Get key for Alice did")
    thrift['alice_key_for_thrift'] = \
        await did.key_for_did(thrift['pool'], thrift['wallet'], thrift['alice_connection_response']['did'])

    print("\"Thrift\" -> Authcrypt \"Loan-Application-Basic\" Proof Request for Alice")
    thrift['authcrypted_apply_loan_proof_request'] = \
        await crypto.auth_crypt(thrift['wallet'], thrift['key_for_alice'], thrift['alice_key_for_thrift'],
                                thrift['apply_loan_proof_request'].encode('utf-8'))

    print("\"Thrift\" -> Send authcrypted \"Loan-Application-Basic\" Proof Request to Alice")
    alice['authcrypted_apply_loan_proof_request'] = thrift['authcrypted_apply_loan_proof_request']

    print("\"Alice\" -> Authdecrypt \"Loan-Application-Basic\" Proof Request from Thrift")
    alice['thrift_key_for_alice'], alice['apply_loan_proof_request'], _ = \
        await auth_decrypt(alice['wallet'], alice['key_for_thrift'], alice['authcrypted_apply_loan_proof_request'])

    print("\"Alice\" -> Get credentials for \"Loan-Application-Basic\" Proof Request")

    search_for_apply_loan_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(alice['wallet'],
                                                                alice['apply_loan_proof_request'], None)

    cred_for_attr1 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'attr1_referent')
    cred_for_predicate1 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'predicate1_referent')
    cred_for_predicate2 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'predicate2_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_loan_proof_request)

    alice['creds_for_apply_loan_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                           cred_for_predicate1['referent']: cred_for_predicate1,
                                           cred_for_predicate2['referent']: cred_for_predicate2}

    alice['schemas'], alice['cred_defs'], alice['revoc_states'] = \
        await prover_get_entities_from_ledger(alice['pool'], alice['did_for_thrift'],
                                              alice['creds_for_apply_loan_proof'],
                                              alice['name'])

    print("\"Alice\" -> Create \"Loan-Application-Basic\" Proof")
    alice['apply_loan_requested_creds'] = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {
            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True}
        },
        'requested_predicates': {
            'predicate1_referent': {'cred_id': cred_for_predicate1['referent']},
            'predicate2_referent': {'cred_id': cred_for_predicate2['referent']}
        }
    })
    alice['apply_loan_proof'] = \
        await anoncreds.prover_create_proof(alice['wallet'], alice['apply_loan_proof_request'],
                                            alice['apply_loan_requested_creds'], alice['master_secret_id'],
                                            alice['schemas'], alice['cred_defs'], alice['revoc_states'])

    print("\"Alice\" -> Authcrypt \"Loan-Application-Basic\" Proof for Thrift")
    alice['authcrypted_alice_apply_loan_proof'] = \
        await crypto.auth_crypt(alice['wallet'], alice['key_for_thrift'], alice['thrift_key_for_alice'],
                                alice['apply_loan_proof'].encode('utf-8'))

    print("\"Alice\" -> Send authcrypted \"Loan-Application-Basic\" Proof to Thrift")
    thrift['authcrypted_alice_apply_loan_proof'] = alice['authcrypted_alice_apply_loan_proof']

    print("\"Thrift\" -> Authdecrypted \"Loan-Application-Basic\" Proof from Alice")
    _, thrift['alice_apply_loan_proof'], authdecrypted_alice_apply_loan_proof = \
        await auth_decrypt(thrift['wallet'], thrift['key_for_alice'], thrift['authcrypted_alice_apply_loan_proof'])

    print("\"Thrift\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
          " required for Proof verifying")

    thrift['schemas'], thrift['cred_defs'], thrift['revoc_defs'], thrift['revoc_regs'] = \
        await verifier_get_entities_from_ledger(thrift['pool'], thrift['did'],
                                                authdecrypted_alice_apply_loan_proof['identifiers'], thrift['name'])

    print("\"Thrift\" -> Verify \"Loan-Application-Basic\" Proof from Alice")
    assert 'Permanent' == \
           authdecrypted_alice_apply_loan_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']

    assert await anoncreds.verifier_verify_proof(thrift['apply_loan_proof_request'], thrift['alice_apply_loan_proof'],
                                                 thrift['schemas'], thrift['cred_defs'], thrift['revoc_defs'],
                                                 thrift['revoc_regs'])

    print("==============================")

    print("==============================")
    print("== Apply for the loan with Thrift - Transcript and Job-Certificate proving  ==")
    print("------------------------------")

    print("\"Thrift\" -> Create \"Loan-Application-KYC\" Proof Request")
    nonce = await anoncreds.generate_nonce()
    thrift['apply_loan_kyc_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'Loan-Application-KYC',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {'name': 'first_name'},
            'attr2_referent': {'name': 'last_name'},
            'attr3_referent': {'name': 'ssn'}
        },
        'requested_predicates': {}
    })

    print("\"Thrift\" -> Get key for Alice did")
    thrift['alice_key_for_thrift'] = await did.key_for_did(thrift['pool'], thrift['wallet'],
                                                           thrift['alice_connection_response']['did'])

    print("\"Thrift\" -> Authcrypt \"Loan-Application-KYC\" Proof Request for Alice")
    thrift['authcrypted_apply_loan_kyc_proof_request'] = \
        await crypto.auth_crypt(thrift['wallet'], thrift['key_for_alice'], thrift['alice_key_for_thrift'],
                                thrift['apply_loan_kyc_proof_request'].encode('utf-8'))

    print("\"Thrift\" -> Send authcrypted \"Loan-Application-KYC\" Proof Request to Alice")
    alice['authcrypted_apply_loan_kyc_proof_request'] = thrift['authcrypted_apply_loan_kyc_proof_request']

    print("\"Alice\" -> Authdecrypt \"Loan-Application-KYC\" Proof Request from Thrift")
    alice['thrift_key_for_alice'], alice['apply_loan_kyc_proof_request'], _ = \
        await auth_decrypt(alice['wallet'], alice['key_for_thrift'], alice['authcrypted_apply_loan_kyc_proof_request'])

    print("\"Alice\" -> Get credentials for \"Loan-Application-KYC\" Proof Request")

    search_for_apply_loan_kyc_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(alice['wallet'],
                                                                alice['apply_loan_kyc_proof_request'], None)

    cred_for_attr1 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr3_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_loan_kyc_proof_request)

    alice['creds_for_apply_loan_kyc_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                               cred_for_attr2['referent']: cred_for_attr2,
                                               cred_for_attr3['referent']: cred_for_attr3}

    alice['schemas'], alice['cred_defs'], alice['revoc_states'] = \
        await prover_get_entities_from_ledger(alice['pool'], alice['did_for_thrift'],
                                              alice['creds_for_apply_loan_kyc_proof'], 'Alice')

    print("\"Alice\" -> Create \"Loan-Application-KYC\" Proof")

    alice['apply_loan_kyc_requested_creds'] = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {
            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
            'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True}
        },
        'requested_predicates': {}
    })

    alice['apply_loan_kyc_proof'] = \
        await anoncreds.prover_create_proof(alice['wallet'], alice['apply_loan_kyc_proof_request'],
                                            alice['apply_loan_kyc_requested_creds'], alice['master_secret_id'],
                                            alice['schemas'], alice['cred_defs'], alice['revoc_states'])

    print("\"Alice\" -> Authcrypt \"Loan-Application-KYC\" Proof for Thrift")
    alice['authcrypted_alice_apply_loan_kyc_proof'] = \
        await crypto.auth_crypt(alice['wallet'], alice['key_for_thrift'], alice['thrift_key_for_alice'],
                                alice['apply_loan_kyc_proof'].encode('utf-8'))

    print("\"Alice\" -> Send authcrypted \"Loan-Application-KYC\" Proof to Thrift")
    thrift['authcrypted_alice_apply_loan_kyc_proof'] = alice['authcrypted_alice_apply_loan_kyc_proof']

    print("\"Thrift\" -> Authdecrypted \"Loan-Application-KYC\" Proof from Alice")
    _, thrift['alice_apply_loan_kyc_proof'], alice_apply_loan_kyc_proof = \
        await auth_decrypt(thrift['wallet'], thrift['key_for_alice'], thrift['authcrypted_alice_apply_loan_kyc_proof'])

    print("\"Thrift\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
          " required for Proof verifying")

    thrift['schemas'], thrift['cred_defs'], thrift['revoc_defs'], thrift['revoc_regs'] = \
        await verifier_get_entities_from_ledger(thrift['pool'], thrift['did'],
                                                alice_apply_loan_kyc_proof['identifiers'], 'Thrift')

    print("\"Thrift\" -> Verify \"Loan-Application-KYC\" Proof from Alice")
    assert 'Alice' == \
           alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
    assert 'Garcia' == \
           alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
    assert '123-45-6789' == \
           alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']

    assert await anoncreds.verifier_verify_proof(thrift['apply_loan_kyc_proof_request'],
                                                 thrift['alice_apply_loan_kyc_proof'],
                                                 thrift['schemas'], thrift['cred_defs'], thrift['revoc_defs'],
                                                 thrift['revoc_regs'])

    print("==============================")

    print(" \"Sovrin Steward\" -> Close and Delete wallet")
    await wallet.close_wallet(steward['wallet'])
    await wallet.delete_wallet(steward['wallet_config'], steward['wallet_credentials'])

    print("\"Government\" -> Close and Delete wallet")
    await wallet.close_wallet(government['wallet'])
    await wallet.delete_wallet(government['wallet_config'], government['wallet_credentials'])

    print("\"Faber\" -> Close and Delete wallet")
    await wallet.close_wallet(faber['wallet'])
    await wallet.delete_wallet(faber['wallet_config'], faber['wallet_credentials'])

    print("\"Acme\" -> Close and Delete wallet")
    await wallet.close_wallet(acme['wallet'])
    await wallet.delete_wallet(acme['wallet_config'], acme['wallet_credentials'])

    print("\"Thrift\" -> Close and Delete wallet")
    await wallet.close_wallet(thrift['wallet'])
    await wallet.delete_wallet(thrift['wallet_config'], thrift['wallet_credentials'])

    print("\"Alice\" -> Close and Delete wallet")
    await wallet.close_wallet(alice['wallet'])
    await wallet.delete_wallet(alice['wallet_config'], alice['wallet_credentials'])

    print("Close and Delete pool")
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    print("Getting started -> done")


async def onboarding(_from, to):
    print("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(_from['name'], _from['name'], to['name']))
    (from_to_did, from_to_key) = await did.create_and_store_my_did(_from['wallet'], "{}")

    print("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from['name'], _from['name'], to['name']))
    await send_nym(_from['pool'], _from['wallet'], _from['did'], from_to_did, from_to_key, None)

    print("\"{}\" -> Send connection request to {} with \"{} {}\" DID and nonce"
          .format(_from['name'], to['name'], _from['name'], to['name']))
    connection_request = {
        'did': from_to_did,
        'nonce': 123456789
    }

    if 'wallet' not in to:
        print("\"{}\" -> Create wallet".format(to['name']))
        try:
            await wallet.create_wallet(to['wallet_config'], to['wallet_credentials'])
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass
        to['wallet'] = await wallet.open_wallet(to['wallet_config'], to['wallet_credentials'])

    print("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(to['name'], to['name'], _from['name']))
    (to_from_did, to_from_key) = await did.create_and_store_my_did(to['wallet'], "{}")

    print("\"{}\" -> Get key for did from \"{}\" connection request".format(to['name'], _from['name']))
    from_to_verkey = await did.key_for_did(_from['pool'], to['wallet'], connection_request['did'])

    print("\"{}\" -> Anoncrypt connection response for \"{}\" with \"{} {}\" DID, verkey and nonce"
          .format(to['name'], _from['name'], to['name'], _from['name']))
    to['connection_response'] = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': connection_request['nonce']
    })
    to['anoncrypted_connection_response'] = \
        await crypto.anon_crypt(from_to_verkey, to['connection_response'].encode('utf-8'))

    print("\"{}\" -> Send anoncrypted connection response to \"{}\"".format(to['name'], _from['name']))
    _from['anoncrypted_connection_response'] = to['anoncrypted_connection_response']

    print("\"{}\" -> Anondecrypt connection response from \"{}\"".format(_from['name'], to['name']))
    _from['connection_response'] = \
        json.loads((await crypto.anon_decrypt(_from['wallet'], from_to_key,
                                              _from['anoncrypted_connection_response'])).decode("utf-8"))

    print("\"{}\" -> Authenticates \"{}\" by comparision of Nonce".format(_from['name'], to['name']))
    assert connection_request['nonce'] == _from['connection_response']['nonce']

    print("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from['name'], to['name'], _from['name']))
    await send_nym(_from['pool'], _from['wallet'], _from['did'], to_from_did, to_from_key, None)

    return from_to_did, from_to_key, to_from_did, to_from_key, _from['connection_response']


async def get_verinym(_from, from_to_did, from_to_key, to, to_from_did, to_from_key):
    print("\"{}\" -> Create and store in Wallet \"{}\" new DID".format(to['name'], to['name']))
    (to_did, to_key) = await did.create_and_store_my_did(to['wallet'], "{}")

    print("\"{}\" -> Authcrypt \"{} DID info\" for \"{}\"".format(to['name'], to['name'], _from['name']))
    to['did_info'] = json.dumps({
        'did': to_did,
        'verkey': to_key
    })
    to['authcrypted_did_info'] = \
        await crypto.auth_crypt(to['wallet'], to_from_key, from_to_key, to['did_info'].encode('utf-8'))

    print("\"{}\" -> Send authcrypted \"{} DID info\" to {}".format(to['name'], to['name'], _from['name']))

    print("\"{}\" -> Authdecrypted \"{} DID info\" from {}".format(_from['name'], to['name'], to['name']))
    sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info = \
        await auth_decrypt(_from['wallet'], from_to_key, to['authcrypted_did_info'])

    print("\"{}\" -> Authenticate {} by comparision of Verkeys".format(_from['name'], to['name'], ))
    assert sender_verkey == await did.key_for_did(_from['pool'], _from['wallet'], to_from_did)

    print("\"{}\" -> Send Nym to Ledger for \"{} DID\" with {} Role"
          .format(_from['name'], to['name'], to['role']))
    await send_nym(_from['pool'], _from['wallet'], _from['did'], authdecrypted_did_info['did'],
                   authdecrypted_did_info['verkey'], to['role'])

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


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Credential Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass  # TODO Create Revocation States

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Credential Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass  # TODO Get Revocation Definitions and Revocation Registries

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
    time.sleep(1)  # FIXME waiting for libindy thread complete
