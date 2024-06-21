import os
import json
import re

from cs50 import SQL
from datetime import date
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
from dateutil import tz
import pytz
from tzlocal import get_localzone

from PIL import Image
from helpers import apology, login_required
import base64
from io import BytesIO



utc_time = datetime.datetime.now(datetime.UTC)
local_time = utc_time.replace(tzinfo=pytz.UTC).astimezone(get_localzone())

print(utc_time)
print(local_time)
