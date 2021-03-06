-- Merchant issuing card.
CREATE TABLE merchant(
    id      SERIAL PRIMARY KEY NOT NULL,
    name    VARCHAR NOT NULL,
    phone   VARCHAR NOT NULL,
    website VARCHAR NOT NULL
);

CREATE TABLE cardtype(
    id              SERIAL PRIMARY KEY NOT NULL,
    name            VARCHAR NOT NULL,
    description     VARCHAR NOT NULL
);

CREATE TABLE pic(
    id      SERIAL PRIMARY KEY NOT NULL,
    path    VARCHAR NOT NULL,
    type    VARCHAR(10) NOT NULL
);

CREATE TABLE cardcategory(
    id              SERIAL PRIMARY KEY NOT NULL,
    name            VARCHAR NOT NULL,
    description     VARCHAR
);

CREATE TABLE card(
    id              SERIAL PRIMARY KEY NOT NULL,
    cardtype_id     INTEGER NOT NULL CONSTRAINT card_card_type_fk REFERENCES cardtype(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    pic_id          INTEGER NOT NULL CONSTRAINT card_pic_fk REFERENCES pic(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    description     VARCHAR NOT NULL,
    originprice     FLOAT8 NOT NULL,
    name            VARCHAR NOT NULL,
    pinying         VARCHAR NOT NULL,
    merchant_id     INTEGER NOT NULL CONSTRAINT card_merchant_fk REFERENCES merchant(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    cardcategory_id INTEGER NOT NULL CONSTRAINT card_cardcategory_fk REFERENCES cardcategory(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION
);

CREATE TABLE account(
    id          SERIAL PRIMARY KEY NOT NULL,
    email       VARCHAR UNIQUE,
    username    VARCHAR UNIQUE,
    status      VARCHAR(5) NOT NULL,
    name        VARCHAR(40),
    mobile      VARCHAR UNIQUE,
    passwd      VARCHAR,
    usertype    VARCHAR(5) NOT NULL
);

CREATE TABLE sellitem(
    id          SERIAL PRIMARY KEY NOT NULL,
    card_id     INTEGER NOT NULL CONSTRAINT sellitem_card_fk REFERENCES card(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    price       FLOAT8 NOT NULL,
    balance     FLOAT8 NOT NULL,
    seller_id   INTEGER NOT NULL CONSTRAINT sellitem_account REFERENCES account(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    status      CHAR(2) NOT NULL,
    ctime       TIMESTAMP NOT NULL,
    expire      TIMESTAMP NOT NULL,
    attr1       VARCHAR(80),
    attr2       VARCHAR(80),
    attr3       VARCHAR(80),
    attr4       VARCHAR(80)
);

CREATE TABLE state(
    id          SERIAL PRIMARY KEY NOT NULL,
    name        VARCHAR NOT NULL
);

CREATE TABLE city(
    id          SERIAL PRIMARY KEY NOT NULL,
    name        VARCHAR NOT NULL
);


CREATE TABLE country(
    id          SERIAL PRIMARY KEY NOT NULL,
    name        VARCHAR NOT NULL
);

CREATE TABLE carrier(
    id          SERIAL PRIMARY KEY NOT NULL,
    name        VARCHAR NOT NULL,
    phone       VARCHAR NOT NULL
);
    

CREATE TABLE payment(
    id          SERIAL PRIMARY KEY NOT NULL,
    cardno      VARCHAR NOT NULL,
    cardtype    VARCHAR(5) NOT NULL
);

CREATE TABLE orders(
    id              SERIAL PRIMARY KEY NOT NULL,
    account_id      INTEGER NOT NULL CONSTRAINT orders_account REFERENCES account(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    time            TIMESTAMP NOT NULL,
    destaddr        VARCHAR(120) NOT NULL,  
    destcity_id     INTEGER NOT NULL CONSTRAINT sellitem_city REFERENCES city(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    deststate_id    INTEGER NOT NULL CONSTRAINT sellitem_state REFERENCES state(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    country_id      INTEGER NOT NULL CONSTRAINT sellitem_country REFERENCES country(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    carrier_id      INTEGER NOT NULL CONSTRAINT sellitem_carrier REFERENCES carrier(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    recvname        VARCHAR NOT NULL,
    recvzip         VARCHAR NOT NULL,
    recvphone       VARCHAR NOT NULL,
    payment_id      INTEGER NOT NULL CONSTRAINT sellitem_payment REFERENCES payment(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    status          VARCHAR(5) NOT NULL
);

CREATE TABLE orderline(
    id          SERIAL PRIMARY KEY NOT NULL,
    order_id    INTEGER NOT NULL CONSTRAINT orderline_orders REFERENCES orders(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    time_id     TIMESTAMP NOT NULL,
    sellitem_id INTEGER NOT NULL CONSTRAINT orderline_sellitem REFERENCES sellitem(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION
);

CREATE TABLE recvaddress(
    id          SERIAL PRIMARY KEY NOT NULL,
    addr1       VARCHAR(80) NOT NULL,
    addr2       VARCHAR(80) NOT NULL,
    city_id     INTEGER NOT NULL CONSTRAINT sendaddress_city REFERENCES city(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    state_id    INTEGER NOT NULL CONSTRAINT sendaddress_state REFERENCES state(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    zip         VARCHAR(80) NOT NULL,
    country_id  INTEGER NOT NULL CONSTRAINT sendaddress_country REFERENCES country(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    account_id  INTEGER NOT NULL CONSTRAINT recvaddress_account REFERENCES account(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION
);

CREATE TABLE sendaddress(
    id          SERIAL PRIMARY KEY NOT NULL,
    addr1       VARCHAR(80) NOT NULL,
    addr2       VARCHAR(80) NOT NULL,
    city_id     INTEGER NOT NULL CONSTRAINT sendaddress_city REFERENCES city(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    state_id    INTEGER NOT NULL CONSTRAINT sendaddress_state REFERENCES state(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    zip         VARCHAR(80) NOT NULL,
    country_id  INTEGER NOT NULL CONSTRAINT sendaddress_country REFERENCES country(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION,
    account_id  INTEGER NOT NULL CONSTRAINT sendaddress_account REFERENCES account(id) MATCH SIMPLE ON UPDATE CASCADE ON DELETE NO ACTION
);
