# Rest handler to generate confs

## Overview

    This app sits on deployment servers, receives payload from the SH app <app-name here>.
  
    The python program decodes the payload and generates inputs.conf and serverclass.conf
  
    Checks for existing app/conf files and adds only new updates. Duplicates are ignored.

## Security

- `/services/receive_payload` requires a login with the `input_conf_generator_write` capability (`default/authorize.conf`).
- Give the account whose token the SH app uses only the `input_conf_generator_sender` role.
- Every field is validated before it is written to `inputs.conf` or `serverclass.conf`.
  Bad input gets a `400` that lists the problems.
- The request body is plain JSON (see the SH app). Requires Splunk Enterprise 10.2+ (Python 3.13/3.14).

Every pull request runs `.github/workflows/validate.yml`. To run it locally:
`python3 -m unittest discover -s tests && python3 ci/validate_app.py`.

## To do
1. Create another handler to send phoning phone list to SH/ or log them and read from the dashboard app.
2. Keep track of updated serverclass, reload them at an interval.


To modify the below 

# to do 
create ability to delete source/app probably in a new endpoint
create ability to update source/app probably in a new endpoint

validate :
app name - can't have space 
any fields can't have space
