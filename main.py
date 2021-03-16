from flask import Flask, render_template, redirect
from flask import request

from twilio.twiml.voice_response import VoiceResponse
from twilio.rest import Client

from dotenv import load_dotenv

import urllib.request

from pprint import pprint

import glob
import os

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

load_dotenv()

account_sid = os.environ['TWILIO_ACCOUNT_SID']
auth_token = os.environ['TWILIO_AUTH_TOKEN']

app = Flask(__name__)


@app.route('/')
def home():
    recordings = get_recordings()
    return render_template(
        'home.html',
        title="My encrypted voicemails",
        recordings=recordings
    )


@app.route('/recording/<sid>', methods=['GET', 'POST'])
def recording_by_sid(sid):
    if request.method == 'GET':
        client = Client(account_sid, auth_token)
        recording = client.recordings(sid).fetch()
        print('recording found', recording.date_created)
        recording_url = "https://api.twilio.com{}".format(recording.uri.replace('.json', ''))
        decrypted_recording_name = recording.sid + '_decrypted.wav'

        if not decrypted_recording_exists(decrypted_recording_name):
            decrypt_recording(recording.encryption_details, recording_url, recording.sid)

        return render_template(
            'recording.html',
            title="Voicemail {} page".format(recording.sid),
            recording=decrypted_recording_name,
            sid=recording.sid,
            path="/recording/{}".format(recording.sid)
        )
    else:
        print('delete file')
        delete_recording(sid)
        return redirect('/')


@app.route("/handle_incoming_call", methods=['GET', 'POST'])
def handle_incoming_call():
    print('call received')
    response = VoiceResponse()
    response.say("Hi, I can't come to the phone right now, please leave a message after the beep")
    response.pause(length=3)

    response.record(
        recording_status_callback='/recording_status_callback',
        recording_status_callback_event='completed')

    response.hangup()
    return str(response)


@app.route("/recording_status_callback", methods=['GET', 'POST'])
def recording_status_callback():
    pprint(request.form)
    return ''


def get_recordings():
    client = Client(account_sid, auth_token)
    recordings = client.recordings.list()
    all_recordings = []
    for record in recordings:
        if record.encryption_details is not None:
            rec = {
                'date_created': record.date_created,
                'sid': record.sid,
                'duration': record.duration,
                'status': record.status,
                'price': record.price,
                'path': "/recording/{}".format(record.sid)
            }
            all_recordings.append(rec)
    return all_recordings


def decrypted_recording_exists(recording_name):
    files = glob.glob('static/recordings/*.wav')
    for f in files:
        if recording_name in f:
            print('File exists', f)
            return True

    print('No files found')
    return False


def decrypt_recording(encryption_details, url, recording_sid):
    urllib.request.urlretrieve(url, 'static/recordings/{}.wav'.format(recording_sid))

    encrypted_cek = encryption_details['encrypted_cek']
    iv = encryption_details['iv']

    private_key = open("private_key.pem", mode="rb")
    key = serialization.load_pem_private_key(private_key.read(), password=None, backend=default_backend())
    private_key.close()

    decrypted_cek = key.decrypt(
        base64.b64decode(encrypted_cek),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decryptor = Cipher(
        algorithms.AES(decrypted_cek),
        modes.GCM(base64.b64decode(iv)),
        backend=default_backend()
    ).decryptor()

    encrypted_recording_file_path = 'static/recordings/{}.wav'.format(recording_sid)
    decrypted_recording_file_path = 'static/recordings/{}_decrypted.wav'.format(recording_sid)
    decrypted_recording_file = open(decrypted_recording_file_path, "wb")
    encrypted_recording_file = open(encrypted_recording_file_path, "rb")

    for chunk in iter(lambda: encrypted_recording_file.read(4 * 1024), b''):
        decrypted_chunk = decryptor.update(chunk)
        decrypted_recording_file.write(decrypted_chunk)

    decrypted_recording_file.close()
    encrypted_recording_file.close()
    print("Recording decrypted Successfully. You can play the recording from " + decrypted_recording_file_path)


def delete_recording(sid):
    client = Client(account_sid, auth_token)
    client.recordings(sid).delete()

    files = glob.glob('static/recordings/*.wav')
    for f in files:
        try:
            if sid in f:
                os.remove(f)
                print(f, ' file deleted')
        except OSError as e:
            print("Error: %s : %s" % (f, e.strerror))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000, debug=True)
