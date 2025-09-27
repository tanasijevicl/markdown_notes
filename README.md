# Baze podataka 1 - podsetnik

## SQL

**SQL** je struktuirani upitni jezik koji omogućava pristup podacima u sistemima za upravljanje relacionim bazama podataka. SQL možemo podeliti na četiri dela:

1. **DDL** (Data Definition Language) - CREATE, DROP, ALTER, RENAME, ...
   
2. **DML** (Data Manipulation Language) - SELECT, INSERT, UPDATE, DELETE

3. **DCL** (Data Control Language) - GRANT, REVOKE

4. **TCL** (Transaction Control Language) - COMMIT, ROLLBACK, ...



Prikaz svih podataka iz tabele (**SELECT**, **FROM**):

```sql
SELECT *
FROM <tabela>
```

Prikaz određenih kolona tabele:

```sql
SELECT <kolona1>, <kolona2>, ...
FROM <tabela>
```

Sortiranje podataka (**ORDER BY**):

```sql
SELECT *
FROM <tabela>
ORDER BY <kolona1> <ASC/DESC>, <kolona2> <ASC/DESC>, ...
```

`ASC` sortira vrednosti u rastućem poretku i ona je podrazumevana. `DESC` sortira vrednosti u opadajućem poretku. Sortiranje može da se radi po nazivu kolone i po rednom broju kolone (numeracija ide od 1).

Prikaz podataka koji ispunjavaju neki uslov (**WHERE**):

```sql
SELECT *
FROM <tabela>
WHERE <uslov1> <logicki_operator> <uslov2> ... 
```

Moguće operacije poređenja: `<, <=, >, >=, =, !=`. Mogući logički operatori: `AND, OR, NOT, BETWEEN`. `BETWEEN` obuhvata obe granične vrednosti.

Prikaz izračunatih kolona i preimenovanje kolona (**AS**):

```sql
SELECT <izraz> AS "<naziv_izraza>"
FROM <tabela>
```

String za preimenovanje kolone se piše u duplim navodnicima. U slučaju jedne reči navodnici mogu da se izostave.

Ispis svih različitih vrednosti unutar jedne kolone (**SELECT DISTINCT**):

```sql
SELECT DISTINCT <kolona>
FROM <tabela>
```

Upoređivanje **NULL** vrednosti:

```sql
SELECT *
FROM <tabela>
WHERE <kolona> <IS/IS NOT> NULL
```

> [!WARNING]
> Upoređivanje NULL vrednosti sa `<, <=, >=, >, =, !=` uvek vraća false.

**Agregatne funkcije**:

```sql
SELECT <FUNCTION>(<kolona>)
FROM <tabela>
```

Agregatne funkcije su `COUNT, MIN, MAX, SUM, AVG`. `AVG` računa prosečnu vrednost samo
onih kolona koje nisu `NULL`, tako i `COUNT` broji samo one kolone koje nisu `NULL`.

Spajanje dve ili više tabela:

```sql
SELECT ...
FROM <tabela1>, <tabela2>, ...
WHERE ...
```

Grupisanje istih vrednosti određene kolone (**GROUP BY**):

```sql
SELECT <podskup_grupisanih_kolona>, <agregatne_funkcije>
FROM <tabela>
GROUP BY <kolona1>, <kolona2>, ...
```

Uslov za grupu (**HAVING**):

```sql
SELECT <podskup_grupisanih_kolona>, <agregatne_funkcije>
FROM <tabela>
GROUP <kolona1>, <kolona2>, ...
HAVING <izraz>
```

Kreiranje tabele (**CREATE TABLE**):

```sql
CREATE TABLE <tabela> <IF NOT EXISTS> ( 
    <kolona> <tip_podatka> <ogranicenja>,  -- Definisanje kolone
    ...
)
```

Tipovi podataka:

- celobrojni tip - `INTEGER`, ...
- realni tip - `REAL`, `DOUBLE`, `FLOAT`, ...
- tekstualni tip - `CHARACTER(<length>)` (statičko alociranje), `VARCHAR(<length>)` (dinamičko alociranje), ...
- numerički tip - `DATE`, `TIME`, `BOOL`, ...

Ograničenja:

- obavezno polje - `NOT NULL`
- jedinstvena vrednost - `UNIQUE`
- uslov - `CHECK (<izraz>)`
- podrazumevana vrednost - `DEFAULT (<izraz>)/<singed_number>/<literal-value>`

> [!IMPORTANT]
> Prilikom definisanja primarnog ključa, stranog ključa ili jedinstvene vrednosti koje se sastoje iz više atributa, potrebno ih je definisati zasebno nakon njihovih pojedinačnih definicija. Njihovo definisanje u nastavku definicije atributa nije moguće.

Dodavanje primarnog ključa (**PRIMARY KEY**):

```sql
<id> <tip_podatka> PRIMARY KEY <AUTOINCREMENT>
```
ili
```sql
<id1> <tip_podatka> ...
<id2> <tip_podatka> ...
...
PRIMARY KEY (id1, id2, ...)
```

Dodavanje stranog ključa: 

```sql
<fid> <tip_podatka> REFERENCES <strana_tabela> (<kolona>) <opcije>
```

Prilikom definisanja stranog ključa može se definisati i šta će desiti sa instancama u zavisnom entitetu prilikom izmene ili brisanja instance iz roditeljskog entiteta. Moguće vrednosti za `ON UPDATE` i `ON DELETE` su:
- `NO ACTION`, `RESTRICT`, `SET NULL`, `SET DEFAULT` i `CASCADE`. 

Podrazumevano je `NO ACTION`.

Kreiranje pogleda (**CREATE VIEW**):

```sql
CREATE VIEW <ime_pogleda> 
    (<ime_kolone1>, <ime_kolone2>, ...)
AS ...

SELECT *
FROM <ime_pogleda>
WHERE <uslov>
```

Uklanjanje pogleda (**DROP VIEW**):

```sql
DROP VIEW <IF EXISTS> <pogled>;
```

Dodavanje u tabelu (**INSERT**):

```sql
INSERT INTO <tabela>
    (<kolona1>, <kolona2>, ...)
VALUES 
    (<vrednost1_k1>, <vrednost1_k2>, ...)
    (<vrednost2_k1>, <vrednost2_k2>, ...)
```

Azuriranje polja tabele (**UPDATE**):

```sql
UPDATE <tabela>
SET <kolona> = <vrednost>
WHERE <id> = <id?>
```

Brisanje iz tabele (**DELETE**):

```sql
DELETE FROM <tabela>
WHERE <id> = <id?>
```

Pretraga (**LIKE**):

```sql
SELECT *
FROM <tabela> T
WHERE T.<kolona> <NOT> LIKE '<format>' <ESCAPE '?'> -- pretraga "_word"
```

Značenje specijalnih karaktera:
- `%` - 0 ili više pojavljivanja nekih karaktera
  - `s%` - poklapa se sa stringom koji počinje sa `s`
  - `%s` - poklapa se sa stringom koji se završava sa `s`
  - `%text%` - poklapa se sa stringom koji u sebi sadrži `text`
- `_` - tačno jedno pojavljivanje nekog (bilo kog) karaktera

Ako tražimo rezervisani znak  (`_`, `%`, `'`, ...) Potrebno je koristiti proizvoljni `ESCAPE` karakter u tekstu.

> [!NOTE]
> LIKE operator je u SQLite case insensitive. Ovo podrazumevano ponašanje menja se sa:
`PRAGMA case_sensitive_like=ON;`, odnosno `PRAGMA case_sensitive_like=OFF`;

Izvlačenje samo određenog broja redova iz rezultata nekog upita (**LIMIT** i **OFFSET**):

```sql
SELECT ...
...
LIMIT <broj_redova> OFFSET <broj_reda>
```

`LIMIT` definiše koliko maksimalno redova treba prikazati od rezultata upita, ako rezultat nema traženi broj redova, onda prikazuje koliko ih ima. `OFFSET` definiše od kog reda u rezultatu treba primeniti `LIMIT`. Mora da je naveden `LIMIT`, izostavljanjem klauzule se podrazumeva kao da je `OFFSET` postavljen na 0. Ukoliko je `LIMIT` negativan onda kao da je postavljen na onoliko redova koliko ima redova u rezultatu. Ukoliko je `OFFSET` negativan onda se ignoriše. `LIMIT` i `OFFSET` moraju biti celobrojne vrednosti.

Nadovezivanje stringova:

```sql
SELECT PosBr || '-' || Naziv AS Mesta
FROM Mesto
```

Ugneždeni upiti mogu biti:
- **Nekorelisani** – ugneždeni upit ne zavisi od spoljašnjih upita. Rezultat
njegovog izvršavanja je isti bez obzira na spoljašnji upit. Može biti izvršen
jednom.

- **Korelisani** – ugneždeni upit zavisi od bar jednog spoljašnjeg upita, tj.
poseduje promenljivi deo čiju vrednost diktira spoljašnji upit. Rezultat
njegovog izvršavanja je promenljiv. Mora biti izvršen za svaki red rezultata
spoljašnjeg upita.

```sql
SELECT K.IdKom, k.Naziv
FROM Komitent k
WHERE (
    -- Korelisani
    SELECT COUNT(*) 
    FROM Racun R 
    WHERE R.IdKom = K.IdKom
) = (
    -- Nekorelisani
    SELECT COUNT(*) 
    FROM Racun 
    WHERE IdKom = 2
) AND K.IdKom != 2
```

> [!NOTE]
> Ugneždeni `SELECT` iskaz može se koristiti u `WHERE` rečenici iskaza `SELECT`, `DELETE`, `UPDATE`.

Operator **(NOT) IN** proverava da li vrednost izraza jeste/nije u skupu

```sql
<izraz> <NOT> IN (<konstanta>, ...)
```

Ukoliko upit vrati bar jedan red `EXISTS` će vratiti `TRUE`, u suprotnom `FALSE`.

```sql
<NOT> EXISTS (<upit>)
```

Nad rezultatima upita-tabelama definisane su skupovne operacije unije, preseka i razlike iako rezultati upita-tabele ne predstavljaju skupove. Skupovne operacije vrše spajanje rezultata upita-tabela po redovima. U opštem slučaju kod rezultata upita-tabela može da postoji više jednakih redova. U slučaju redno povezanih upita sa skupovnim operacijama, operacije se izvršavaju redom.

- `UNION` – unija
- `UNION ALL` – unija sa ponavljanjem
- `INTERSECT` – presek
- `EXCEPT` – razlika

Za izvršavanje skupovnih operacija potrebno je da rezultati upita-tabele koje se spajaju zadovoljavaju **unijsku kompatibilnost** (*union-compatible*), a to znači da tabele koje se spajaju moraju da imaju:
1) Isti broj kolona
1) Kolone koje se spajaju moraju da imaju isti domen (tip, ograničenja)

Operator **CASE**:

```sql
SELECT ...,
CASE <kolona>
    WHEN <case1> THEN <vrednost1>
    WHEN <case2> THEN <vrednost2>
    ...
    ELSE <vrednostN>
END AS <ime_kolone>
FROM <tabela>

SELECT ..., 
CASE
    WHEN <izraz1> THEN <vrednost1>
    WHEN <izraz2> THEN <vrednost2>
    ...
    ELSE <vrednostN>
END AS <ime_kolone>
```

Kako bi odvojili kriterijum po kome spajamo tabele radi preglednosti, moguće je proširiti `FROM` klauzulu sa nekim od **JOIN** operatora.

- `CROSS JOIN` – spajanje Dekartovim proizvodom
- `INNER JOIN` – unutrašnje spajanje
- `OUTER JOIN` – spoljašnje spajanje

`CROSS JOIN` predstavlja spajanje Dekartovim proizvodom, gde se svaki red prve tabele uparuje sa svakim redom druge tabele. Ako prva tabela ima X redova, a druga tabela Y redova onda rezultat ima X*Y redova.

```sql
SELECT *
FROM <tabela1>, <tabela2>

SELECT *
FROM <tabela1> CROSS JOIN <tabela2>
```

`INNER JOIN` predstavlja spajanje kod kog je potrebno zadovoljiti neki uslov. Uslov se definiše pomoću ključne reči `ON`.

```sql
SELECT *
FROM <tabela1>, <tabela2>
WHERE <tabela1.id1> = <tabela2.id2>

SELECT *
FROM <tabela1> <INNER> JOIN <tabela2> ON (<tabela1.id> = <tabela2.id>)
```

> [!NOTE]
> Reč `INNER` je podrazumevana, tako da je moguće umesto `INNER JOIN` napisati samo `JOIN`. Isti rezultat bi se dobio i kada bi se izostavile i obe ključne reči `INNER JOIN`.

Kako se tabele najčešće spajaju po primarnim-stranim ključevima i tom prilikom se najčešće atributi zovu isto, onda je uveden ključna reč `USING`, čime se implicitno izjednačavaju navedene kolone iz obe tabele.

```sql
SELECT *
FROM <tabela1> INNER JOIN <tabela2>
WHERE <tabela1.id> = <tabela2.id>

SELECT *
FROM <tabela1> <INNER> JOIN <tabela2> USING (<id>)
```

Kako se izbeglo stalno navođenje istoimenih kolona pri korišćenju `USING` ključne reči, onda se uvelo novo spajanje `NATURAL JOIN` (prirodno spajanje) koje izjednačava sve istoimene kolone iz tabela koje se spajaju.

```sql
SELECT *
FROM <tabela1> <INNER> JOIN <tabela2> USING (<id>)

SELECT *
FROM <tabela1> NATURAL JOIN <tabela2>
```

> [!WARNING]
> Ukoliko u tabelama postoje kolone sa istim nazivom, a sa drugačijim značenjem, onda će doći do pogrešnog spajanja.

U bazama podataka postoje tri vrste `OUTER JOIN`-a (spoljašnjih spajanja):
- `LEFT OUTER JOIN`
- `RIGHT OUTER JOIN`
- `FULL OUTER JOIN`

Navedena spajanja vrše spajanje po zadatom kriterijumu (moguće kombinovati sa `ON`, `USING`, `NATURAL`). Redovi koji ispunjavaju uslov se spoje (kao `INNER JOIN`) i kao takvi ulaze u rezultat, a redovi koji ne ispunjavaju uslov se proširuju sa `NULL` vrednostima i onda ulaze u rezultat. `FULL OUTER JOIN` služi za kreiranje denormalizovanih tabela.

Funkcija `COALESCE(param1, param2, ...)` vraća vrednost prvog parametra koji nije `NULL`. Ukoliko svi parametri imaju `NULL` vrednost, vraća se NULL.

```sql
COALESCE(param1, param2, ...)

CASE WHEN param1 IS NOT NULL THEN param1
WHEN param2 IS NOT NULL THEN param2
…
ELSE NULL
END
```

Funkcija `NULLIF(param1, param2)` vraća `NULL` u slučaju da su `param1` i `param2` jednaki u suprotnom vraća `param1`.

```sql
NULLIF(param1, param2)

CASE 
    WHEN param1 = param2 THEN NULL 
    ELSE param1 
END
```

Ugrađene funkcije u SQLite-u:
- `abs(X)` – apsolutna vrednost
- `length(X)` – dužina tekstualnog polja
- `last_insert_rowid()` – poslednji dodat id
- `min(X, Y, ...)` – minimalna vrednost
- `replace(X, Y, Z)` – zamena podteksta u tekstu
- `substr(X, Y, Z)` – dohvatanje podteksta iz teksta

Ako se u upitu koristi više puta isti podupit, može se koristiti ***Common Table Expressions*** (**CTE**). 

```sql
WITH <cte_name> AS (SELECT ...)
```

> [!NOTE]
> CTE predstavlja pomoćnu tabelu koja je deo samog upita. Za slične potrebe smo koristili VIEW, međutim VIEW predstavlja deo šeme.

Korišćenje rekurzije (**WITH RECURSIVE**):

1. Izvrši *initial-select* i rezultat stavi u red (*queue*)
2. Sve dok red nije prazan:
   1. Uzmi jednu torku iz reda
   2. Ubaci uzetu torku u rekurzivnu tabelu (*cte-table-name*)
   3. Pretvaraj se da je uzeta torka jedina torka u rekurzivnoj tabeli i pokreni *recursive-select*, pa dodaj rezultat u red (*queue*)

```sql
WITH RECURSIVE <naziv_rekurzije> (var1, var2, ...)
    VALUES(var1_val, var2_val, ...)     -- inicijalne vrednosti promenljivih
    UNION <ALL>
    SELECT ...      -- rekurzivni deo
```

`ORDER BY` u rekurzivnom `SELECT`-u (posle `UNION` ili `UNION ALL`) sortira red za čekanje, pa definiše koji će red iz *queue*-a biti sledeći uzet. `LIMIT` definiše koliko redova maksimalno može biti u rekurzivnoj tabeli `OFFSET` definiše koliko prvih redova ne staviti iz *queue* u rekurzivnu tabelu (ovi redovi će biti uzeti iz *queue* i obrađeni kao i ostali).
