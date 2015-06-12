"""
Database API
"""

from peewee import *

log = None
database = PostgresqlDatabase('test')

def set_logger(weblog):
    global log
    log = weblog


class Merchant(Model):
    name = CharField(null = False)
    phone = CharField(null = False)
    website = CharField(null = False)
    class Meta:
        database = database


class Payment(Model):
    cardno = CharField(null = False)
    cardtype = CharField(null = False)
    class Meta:
        database = database


class Carrier(Model):
    name = CharField(null = False)
    phone = CharField(null = False)
    class Meta:
        database = database


class Country(Model):
    name = CharField(null = False)
    class Meta:
        database = database


class CardType(Model):
    name = CharField(null = False)
    description = CharField(null = False)
    class Meta:
        database = database


class Pic(Model):
    path = CharField(null = False)
    type = CharField(null = False)
    class Meta:
        database = database


class State(Model):
    name = CharField(null = False)
    class Meta:
        database = database


class CardCategory(Model):
    name = CharField(null = False)
    description = CharField()
    class Meta:
        database = database


class Card(Model):
    cardtype = ForeignKeyField(CardType, null = False)
    pic = ForeignKeyField(Pic, null = False) 
    description = CharField(null = False)
    originprice = FloatField(null = False)
    name = CharField(null = False)
    pinying = CharField(null = False)
    merchant = ForeignKeyField(Merchant)
    cardcategory = ForeignKeyField(CardCategory)
    class Meta:
        database = database


class Account(Model):
    email = CharField(unique = True)
    username = CharField(unique = True)
    status = CharField(null = False)
    name = CharField()
    mobile = CharField(unique = True)
    passwd = CharField()
    usertype = CharField(null = False)
    class Meta:
        database = database


class City(Model):
    name = CharField(null = False)
    class Meta:
        database = database


class Orders(Model):
    account = ForeignKeyField(Account, null = False)
    time = TimeField(null = False)
    destaddr = CharField(null = False)
    destcity = ForeignKeyField(City, null = False)
    deststate = ForeignKeyField(State, null = False)
    country = ForeignKeyField(Country, null = False)
    carrier = ForeignKeyField(Carrier, null = False)
    recvname = CharField(null = False)
    recvzip = CharField(null = False)
    recvphone = CharField(null = False)
    payment = ForeignKeyField(Payment, null = False)
    status = CharField(null = False)
    class Meta:
        database = database


class SellItem(Model):
    card = ForeignKeyField(Card, null = False)
    price = FloatField(null = False)
    balance = FloatField(null = False)
    seller = ForeignKeyField(Account, null = False)
    status = CharField(null = False)
    ctime = TimeField(null = False)
    expire = TimeField(null = False)
    attr1 = CharField()
    attr2 = CharField()
    attr3 = CharField()
    attr4 = CharField()
    class Meta:
        database = database


class OrderLine(Model):
    orders = ForeignKeyField(Orders, null = False)
    time = TimeField(null = False)  
    sellitem = TimeField(SellItem, null = False)
    class Meta:
        database = database


class RecvAddress(Model):
    addr1 = CharField(null = False)
    addr2 = CharField(null = False)
    city = ForeignKeyField(City, null = False)
    state = ForeignKeyField(State, null = False)
    zip = CharField(null = False)
    country = ForeignKeyField(Country, null = False)
    account = ForeignKeyField(Account, null = False)
    class Meta:
        database = database 


class SendAddress(Model):
    addr1 = CharField(null = False)
    addr2 = CharField(null = False)
    city = ForeignKeyField(City, null = False)
    state = ForeignKeyField(State, null = False)
    zip = CharField(null = False)
    country = ForeignKeyField(Country, null = False)
    account = ForeignKeyField(Account, null = False)
    class Meta:
        database = database
