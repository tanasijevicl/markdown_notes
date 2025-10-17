# SRV - predavanja

## Osnovni pojmovi i koncepti sistema za rad u realnom vremenu

**Sistem u realnom vremenu** predstavlja sistem koji mora da zadovolji eksplicitan (ograničen) zahtev za vremenom odziva ili u protivnom rizikuje nastanak katastrofalnih posledica, uključujući otkaz sistema.

***Soft real-time system*** je onaj sistem čije se performanse degradiraju ali bez katastrofalnih posledica usled otkaza sistema koji nastaje u slučaju kada sistem ne zadovolji specificirane zahteve za vremenom odziva sistema.

***Hard real-time system*** je onaj sistem kod koga slučaj nezadovoljenja specificiranog zahteva za vremenom odziva sistema može dovesti do potpunog i katastrofalnog otkaza sistema.

***Firm real-time system*** je onaj sistem kod koga nekoliko slučajeva nezadovoljenja specificiranog zahteva za vremenom odziva neće dovesti do potpunog otkaza, ali nezadovoljenje više od nekoliko specificiranih zahteva za vremenom odziva sistema može dovesti do potpunog i katastrofalnog otkaza sistema.

**Namenski sistem** (*embedded system*) je procesorski sistem sa čvrsto povezanim integrisanim hardverom i softverom i koji je dizajniran da izvrši određenu funkciju. 

U softverskim sistemima, svaka pojava koja dovodi do nesekvencijalne promene programskog brojača smatra se promenom u toku izvršavanja programa, tj. događajem (***event***).

**Sinhroni događaji** su oni događaji koji se pojavljuju (pozivi procedura, itd.) ili se mogu pojaviti (uslovni skokovi, itd.) u predvidljivom vremenskom trenutku tokom izvršavanja programa.

**Asinhroni događaji** se pojavljuju u nepredvidivim trenucima vremena za vreme izvršavanja programa i uobičajeno su izazvani od strane spoljašnjeg izvora.

Događaji koji se ne javljaju u regularnim intervalima vremena (ili periodama vremena) nazivaju se **aperiodični**. U slučaju kada se aperiodični događaji vrlo retko pojavljuju, nazivaju 
se **sporadičnim događajima**.

Sistem je **deterministički**, ako je za svako moguće stanje i za svaku kombinaciju ulaza, moguće odrediti naredno stanje sistema i jedinstveni set izlaza.

**Opterećenje procesora** (CPU *utilization* - *U*) je mera vremena izražena u procentima kada se procesor ne nalazi u praznom hodu (*idle-time*). **Vrednost faktora opterećenja** (*U*) računa se kao zbir svih faktora opterećenja za svaki periodični ili aperiodični zadatak. 

U slučaju kada sistem ima $n ≥ 1$ periodičnih zadataka, sa periodom izvršavanja $p_i$, odnosno učestanosti izvršavanja $f_i = 1 / p_i$ , pri čemu maksimalno vreme izvršenja (najgori slučaj) zadatka iznosi $e_i$, vrednost faktora opterećenja biće data izrazom:

$$
U = \sum_{i=1}^n \frac{e_i}{p_i} = \sum_{i=1}^n u_i
$$

> [!NOTE]
> Bitno je napomenuti da je krajnji rok (*deadline*) za periodični task $i$, označen sa $d_i$ u tipičnom slučaju predstavlja vreme trajanja ciklusa i kritičan je parametar pri projektovanju zadatka.

Za aperiodične i sporadične zadatke, **vrednost faktora opterećenja** izračunava se na osnovu maksimalne vrednosti vremena izvršenja i minimalne vrednosti intervala između dva uzastopna zahteva za izvršenjem zadatka. Uvek se uzima najgori slučaj obzirom da je realno moguć.

**CPU arhitekture** - Zavisno od toga da li su programska i memorija podataka, integrisani ili razdvojeni, reč je o jednoj od dva osnovna tipa arhitektura:

- **Von-Neumann arhitektura** - Kod ove arhitekture, programu i podacima se pristupa preko zajedničke magistrale. Naravno ovo može dovesti do niza problema u vidu konflikata pristupa memoriji (von Neumann bottleneck), koji rezultiraju u odgovarajućim nepoželjnim kašnjenjima. Poboljšanja arhitekture sistema u formi upotrebe upotrebe keš memorija (*caching*), protočne obrade (*pipelining*) ili upotrebe koprocesora (*coprocessing*).

- **Harvard arhitektura** - Ova arhitektura zahteva da se program i podaci nalaze u odvojenim adresnim prostorima kojima se pristupa preko odvojenih magistrala. Na ovaj način je obezbeđeno da pristup programskom kodu nije u konfliktu sa pristupom podacima, čime su performanse sistema poboljšane.

**RISC arhitektura** poseduje jednostavan, nepromenljiv set instrukcija, koje se uobičajeno izvršavaju u jednom ili dva taktna ciklusa. Takođe, RISC arhitekture imaju mali broj instrukcija i podržavaju svega nekoliko modova adresiranja. Rezultat je da je izvršavanje instrukcija veoma brzo.

**CISC arhitektura** je karakterisana kompleksnim mikro-kodovanim setom instrukcija, koji zahteva veći broj taktnih ciklusa za izvršavanje instrukcija. Međutim, set instrukcija je mnogo moćniji i pruža udobnost prilikom programiranja.

**Formati instrukcija**:

- **Stek arhitektura** - Ova arhitektura sa 0-adresnim formatom instrukcija, u kodu instrukcije ne podržava eksplicitne operande, već su svi operandi organizovani preko steka.

- **Arhitektura sa akumulatorom** - Ova arhitektura sa 1-adresnim formatom instrukcija, podrazumeva upotrebu akumulator registra kao izvorišta za jedan od operanada i kao odredišni registar, dok se drugi operand eksplicitno navodi u kodu instrukcije.

-  **2-adresni format instrukcija** - Kod ove arhitekture specificiraju se oba operanda, pri čemu se jedan od njih ujedno koristi kao odredište, gde se smešta rezultat operacije.

- **3-adresni format instrukcija** - Kod ove arhitekture, oba operanda i odredište operacije se navode eksplicitno u okviru naredbe. Ova arhitektura je ujedno najfleksibilnija, ali kao rezultat imamo najveću veličinu instrukcija.

**Tipovi dostupnih instrukcija**:

- **Aritmetičko logičke instrukcije** - U ovoj grupi instrukcija nalaze se sve instrukcije koje vrše izračunavanje (npr. `ADD`, `SUB`, `MUL`, ...), logičke operacije (`AND`, `OR`, `XOR`, ...), instrukcije za rad na nivou bita (setovanje, resetovanje i testiranje bita), kao i operacije pomeranja (*shift operations*).

- **Instrukcije za prenos podataka** - Ove instrukcije se koriste za prenos podatka između dva registra, između registara i memorijske lokacije ili između memorijskih lokacija. To su uobičajene instrukcije za pristup memoriji tipa `LOAD`, `STORE`, ali i operacije za rad sa 
stekom `PUSH` i `POP`.

- **Instrukcije promene programskog toka** - Ovde se nalaze sve instrukcije koje mogu uticati na tok izvršavanja programa, što uključuje instrukcije skoka, koje postavljaju programski brojač na novu adresu, instrukcije uslovnih skokova, pozivi procedura, kao i instrukcije povratka iz procedura i prekidnih rutina `RET` ili `RETI`.

- **Kontrolne instrukcije** - U ovu grupu instrukcije spadaju sve instrukcije koje utiču na rad samog kontrolera, kao npr. `NOP` instrukcija. U ovu grupu spadaju i sve instrukcije koje se koriste za prelazak kontrolera u mod smanjene potrošnje, reset kontrolera, kontrolu moda rada za namene debagovanja i sl.

**Adresni modovi**:

- **Neposredno adresiranje** (*immediate*/*literal*) - Kod ovog moda adresiranja operand je konstanta. 

- **Registarsko adresiranje** (*register*) - Kod ovog moda adresiranja operand je registar koji sadrži vrednost ili koji se koristi za smeštanje rezultata operacije.

- **Direktno adresiranje** (*direct*/*absolute*) - Operand predstavlja memorijsku lokaciju.

- **Registarsko indirektno** (*register indirect*) - U ovom modu adresiranja, specificiran je registar, ali on sadrži memorijsku adresu izvorišta ili odredišta operacije. Dakle, instrukcije pristupa memorijskoj lokaciji a ne registru.

- **Adresiranje sa auto-inkrementiranjem** - Ovaj adresni mod predstavlja varijantu indirektnog adresiranja, pri čemu se specificirani registar inkrementira ili pre ili posle pristupa memorijskoj lokaciji.
 
- **Adresiranje sa auto-dekrementiranjem** - Slično kao u prethodnom slučaju, ovaj adresni mod se koristi prilikom procesiranja podataka organizovanih u formi niza. 

- **Bazno adresiranje** (*displacement*/*based*) - Kod ovog moda adresiranja, specificira se konstanta i registar. Sadržaj registra se dodaje na konstantu i tako se formira adresa memorijske lokacije kojoj se pristupa. Ovaj način adresiranja se takođe koristi za pristup članovima niza, pri čemu konstanta predstavlja baznu adresu, dok sadržaj registra predstavlja vrednost indeksa člana niza. 

- **Indeksno adresiranje** - U ovom slučaju specificiraju se dva registra, čiji se sadržaj sabira, čime se formira adresa memorijske lokacije. Kod nekih kontrolera koristi se specijalni registar kao indeksni registar.

- **Memorijsko indirektno adresiranje** - U ovom slučaju specificira se registar koji sadrži adresu memorijske lokacije. Međutim sadržaj memorijske lokacije se interpretira kao adresa na finalnu memorijsku lokaciju kojoj se pristupa. Ovaj mod je koristan za npr. tabele sa skokovima.

| adresiranje (mod)      | primer          | rezultat                       |
| ---------------------- | --------------- | ------------------------------ |
| neposredno             | ADD R1, #5      | R1 <- R1 + 5                   |
| registarsko            | ADD R1, R2      | R1 <- R1 + R2                  |
| direktno               | ADD R1, 100     | R1 <- R1 + M[100]              |
| registarsko indirektno | ADD R1, (R2)    | R1 <- R1 + M[R2]               |
| auto-inkrement         | ADD R1, (R2)+   | R1 <- R1 + M[R2], R2 <- R2 + d |
| auto-dekrement         | ADD R1, -(R2)   | R1 <- R1 + M[R2], R2 <- R2 - d |
| bazno                  | ADD R1, 100(R2) | R1 <- R1 + M[100+R2]           |
| indeksno               | ADD R1, (R1+R3) | R1 <- R1 + M[R2+R3]            |
| memorijsko indirektno  | ADD R1, @(R2)   | R1 <- R1 + M[M[R2]]            |

**Instrukcijski set** se naziva **ortogonalnim** ukoliko se može koristiti svaka instrukcija sa bilo kojim od adresnih modova. 

Ukoliko je pristup memorijskoj lokaciji omogućen samo preko upotrebe specijalnih instrukcija (`LOAD`, `STORE`), i ako se npr. aritmetičke instrukcije izvršavaju samo nad registrima, onda se takva arhitektura naziva ***load*/*store* arhitektura**.

Ukoliko određeni set registara ima istu opštu funkciju (za razliku od specifičnih registara tipa PC ili SP), onda se takvi registri nazivaju **registri opšte namene** (*general purpose registers*).

Tipovi memorija prema nameni:

- **Register file** - Obična relativno mala memorija integrisana u CPU koja se koristi za privremeno smeštanje vrednosti sa kojima operiše CPU.

- **Data memory** - Ova memorija je značajno veća od memorije korišćene za register file. Podaci koji su smešteni u njoj su validni sve vreme dok je CPU pod napajanjem. Dodavanje eksterne memorije ovog tipa zahteva različita integrisana kola, samim tim i povećava cenu sistema, tako da je kod mikrokontrolera ovaj tip memorije integrisan na samom čipu.

- **Instruction memory** - Ovo je relativno velika spoljna memorija (kod većine CPU), koja kod *von-Neumann*-ove arhitekture može biti fizički ista memorija kao i memorija za podatke. Kod mikrokontrolera, programska memorija je uobičajeno integrisana na istom čipu.

- Registri za protočnu obradu, keš memorije, različiti baferi i sl.

Poluprovodničke memorije:

- ***Volatile* memorije** predstavljaju tip memorije koje zahtevaju kontinualno napajanje da se ne bi izgubio njihov sadržaj. Dosta brže od *non-volatile* memorija.

    - **SRAM memorija** - čip se sastoji od niza ćelija (niza flip-flopova), od kojih je svaka sposobna da sačuva jedan bit informacije, i svaka se sastoji od 6 tranzistora, nema osvežavanja sadržaja. Brže ali skuplje od DRAM-a.
    - **DRAM memorija** - se sastoji od 1T ćelija i potrebna je posebna logika za osvežavanje sadržaja (*refresh logic*).

- ***Non-volatile* memorije** predstavljaju tip memorije čiji sadržaj je očuvan i nakon gubitka napajanja.

    - ***Read Only Memory*** (ROM) - kod ovog tipa memorije, proizvođač čipa upisuje odgovarajući sadržaj memorije prilikom fabrikacije čipa. Kao alternativa, dostupan je PROM (*Programmable* ROM) tip memorije, koji ima sličnu strukturu baziranu na memorijskim ćelijama, pri čemu svaka ćelija sadrži jedan silicijumski osigurač. OTP (*One Time Programmable*) mikrokontroleri koriste PROM memoriju za programsku memoriju na čipu.
    - ***Erasable Programmable* ROM** (EPROM) - kod ovog tipa memorije proces programiranja memorije nije destruktivan. Interval ponovnog programiranja EPROM-a je reda veličine 10-tak godina. Postupak brisanja EPROM-a pomoću izlaganja silicijumskog čipa UV zracima. Kod EEPROM, proces brisanja se vrši električnim putem, pri čemu se primenom višeg napona uklanjanju elektroni sa plivajućeg gejta FET tranzistora. Sa druge strane, EEPROM čipovi su limitirani brojem ciklusa brisanja/upisa (oko 100.000).
    - **Flash EEPROM memorije**, koje predstavljaju varijantu EEPROM memorije kod koje nije moguće postići brisanje svake pojedinačne adrese, već većih blokova ili cele memorije. Na ovaj način je integrisana logika pojednostavljena, što je uticalo na smanjenje cene komponente. U poređenju sa EEPROM memorijama treba napomenuti da je broj garantovanih ciklusa upisa/čitanja, kod Flash EEPROM memorije smanjen na reda 10.000 ciklusa. **NVRAM** se može realizovati dodavanjem male integrisane baterije na SRAM čip ili kombinovanjem SRAM i EEPROM u jednom čipu, pri čemu se po uključenju napajanja sadržaj EEPROM-a kopira u SRAM i obrnuto.

***Big Endian*** - Kod *Big Endian* arhitekture ako se vrši upis reči 
0x1234 na adresu 0x0100, viši bajt 0x12 će biti upisan na adresu 
0x0100, dok će niži bajt 0x34 biti upisan na adresu 0x0101.

***Little Endian*** - Kod *Little Endian* arhitekture pristup memoriji se vrši u obrnutom redosledu. Prilikom upisa reči 0x1234 na adresu 0x0100, sadržaj lokacije 0x0100 biće 0x34, dok je sadržaj lokacije 0x0101, 0x12.

**Prekid** predstavlja hardverski signal koji inicira događaj. Prekidi mogu biti inicirani od strane spoljašnjih uređaja ili interno ukoliko CPU poseduje tu mogućnost. Postoje instrukcije za omogućavanje ili onemogućavanje prekida (atomske instrukcije).

## Uvod u sisteme u realnom vremenu

**RTOS** je program koji "planira" izvršavanje delova koda po vremenskom principu, omogućava upravljanje resursima sistema (CPU time i memorija), i pruža podršku za razvoj koda.

Karakteristike RTOS-a i GPOS-a:

- RTOS – linearni memorijski model (aplikacije i RTOS u istom memorijskom prostoru; aplikacija pristupa HW resursima sistema preko poziva API funkcija RTOS-a).

- Linux (GPOS, monolitni kernel; aplikacije i OS u odvojenom memorijskom prostoru; pristup HW sistema preko poziva objekata i servisa kernela)

***Board Support Package*** (BSP) - Skup programa koji obezbeđuje vezu između operativnog sistema i hardvera sistema, obezbeđujući pokretanje OS na specifičnoj platformi:

- Inicijalizacija hardvera sistema (*boot firmware*).

- Specifične rutine za rad sa hardvera sistema koje se koriste od strane OS i drajvera uređaja (*device driver*).

Osnovne komponente **kernela** operativnog sistema:

- **Raspoređivač** (*Scheduler*) - Deo operativnog sistema koji je implementiran u svakom kernelu i koji na osnovu algoritama raspoređivanja (prioritetno, round-robin, preemptive raspoređivanje...) određuje koji se programski posao izvršava na sistemu u nekom trenutku.

- **Objekti** – specijalne konstrukcije kernela koji podržavaju razvoj *real-time* aplikacija za namenske sisteme (*task* objekti, semafori, redovi poruka, ...).

- **Servisi** – predstavljaju dodatne funkcionalnosti operativnog sistema koje omogućavaju upravljanje resursima sistema, tj. hardverskim komponentama sistema, podacima, memorijom, vremenom.

**Rasporedljiv entitet** predstavlja objekat kernela koji može učestvovati prilikom raspoređivanja vremena izvršavanja na sistemu, koje se obavlja prema predefinisanom algoritmu raspoređivanja (GPOS – *thread*, proces; RTOS – *task*).

***Multitasking*** - izvršavanje više *task*-ova tako da se sa stanovišta aplikacije oni konkurentno izvršavaju, dok se zapravo, sa stanovišta operativnog sistema, oni izvršavaju sekventno. *Multitasking* je implementiran tehnikom **vremenskog multipleksiranja**.

**Hardverski prekid** predstavlja signal koji je generisan od strane periferijskog uređaja i koji je signaliziran CPU. Kao posledica, CPU izvršava prekidnu rutinu koja obavlja odgovarajuće akcije kao odgovor na prekid.

**Softverski prekid** je sličan hardverskom prekidu u tome što jedan softverski modul prebacuje kontrolu drugom. Osnovna razlika između hardverskog i softverskog prekida je mehanizam iniciranja. Softverski prekid se može klasifikovati kao sinhroni događaj iniciran kao izuzetak ili preko poziva `INT` instrukcije.

**Izuzetak** (*exception*) predstavlja interno generisani prekid iniciran od strane programa koji je pokušao da izvrši nepredviđenu ili nedozvoljenu operaciju.

Sinhronizovani pristup resursima koji su deljeni od strane prekidne rutine i drugih programskih tokova se obično kontroliše preko **onemogućavanja prekida** u delu koda programskog toka aplikacije, koji se odnosi na operacije pristupa tom deljenom resursu. Ovaj model sinhronizacije direktno utiče na performanse.

> [!IMPORTANT]
> Blokirajući mehanizmi sinhronizacije se ne koriste unutar prekidne rutine. Ako su prekidi onemogućeni, odlaže se procesiranje događaja, te je stoga neophodno da kritični delovi koda u kojima su prekidi onemogućeni, budu što je moguće kraći.

***Foreground task*-ovi** se raspoređuju za izvršavanje prema različitim pravilima raspoređivanja izvršavanja taskova i uključuju *task*-ove kontrolisane prekidima.

***Background task*-ovi** se izvršavaju u formi cikličnih poslova koji obavljaju manje vremenski kriticne poslove (programske petlje).

Svaki put kada je novi *task* kreiran, kernel takođe kreira pridruženi **kontrolni blok *task*-a** (*Task Control Block* - TCB), koji sadrži strukture podataka sistema koje kernel koristi za održavanje potrebnih informacija vezanih za dati *task*. U opštem slučaju **kontekst *task*-a** treba da sadrži minimalni set informacija neophodan za sigurno/ispravno nastavljanje izvršavanja *task*-a, nakon što je prethodno njegovo izvršavanje prekinuto.

**Dispečer** (*dispatcher*) je softverski modlu koji je zadužen da izvrši potrebnu promenu konteksta.

**Prioritetni algoritmi** raspoređivanja se klasifikuju u:

- Algoritme sa fiksnim (statičkim) prioritetom
    - *Rate-monotonic* (RM)
    - *Deadline-monotonic* (DM)
  
- Algoritme sa dinamičkim prioritetom
    - *Earliest – Deadline First* (EDF)
    - *First-In-First-Out* (FIFO)
    - *Last-In-First-Out* (LIFO)
    - *Round-Robin* (RR)
    - *Least-Slack-Time-first* (LST)

***Non-Preemptive*** algoritmi su projektovani tako da se ne prekida izvršavanje *task* rutine čije je izvršavanje započeto prema dodeljenom vremenu servisiranja. Dakle rutina za zamenu konteksta se poziva od strane OS tek nakon što je *task* završio izvršavanje ili je blokiran.

***Preemptive*** algoritmi raspoređivanja vode računa da se na sistemu izvršava onaj *task* sa najvećim prioritetom na listi spremnih *task*-ova. Rutina za zamenu konteksta se poziva uobičajeno po isteku programiranog vremenskog intervala (hardverski tajmer).

***Round-robin*** raspoređivanje obezbeđuje svakom *task*-u podjednako procesorsko vreme za njegovo izvršavanje (*time slice*), dok  ***Priority Round-robin*** raspoređivanje obezbeđuje svakom *task*-u istog prioriteta podjednako procesorsko vreme za njegovo izvršavanje (*time slice*), gde *task*-ovi najvišeg prioriteta prvi dobijaju procesor.

Opšti **model periodičnih *task*-ova** podrazumeva periodični *task* u formi sekvence instanci *task*-a koje pristižu na izvršavanje u regularnim vremenskim intervalima.

- Vreme izbacivanja ili pristizanja za izvršavanje $r_{i,j}$ - vreme aktivacije j-te instance *task*-a $\tau_i$. 
- Faza $\phi_i$ - vreme početka prve instance *task*-a $\tau_i$.
- Vreme odziva - vreme proteklo između aktivacije *task*-a i završetka njegovog izvršavanja.
- Apsolutni krajnji rok $d_i$ - vreme do kada izvršavanje instance *task*-a mora biti.
- Relativni krajnji rok $D_i$ (> vreme odziva *task*-a) - maksimalno vreme odziva *task*-a/instance od trenutka pojavljivanja
- Mera labavosti u izvršenju *task*-a/instance $L_i$ - indikacija urgentnosti ili zaostajanja u izvršavanju *task*-a (zavisi od preostalog vremena izvršavanja i krajnjeg roka)
- Period $p_i$ - minimalno trajanje vremenskog intervala između završetka dve uzastopne instance *task*-a.
- Vreme izvršavanja $e_i$ - maksimalno vreme (WCET) potrebno za završetak izvršavanja *task*-a u slučaju da se on samostalno izvršava i da poseduje kontrolu nad svim potrebnim resursima.

Uprošćeni *task* model:

- **Period** $p$ - minimalno trajanje vremenskog intervala između dva uzastopna trenutka kada je *task* spreman za izvršavanje.
- **Vreme izvršavanja** $e$ - maksimalno vreme potrebno za završetak izvršavanja *task*-a u 
slučaju da se on samostalno izvršava na sistemu.
- **Relativni krajnji rok** $D$ - maksimalno vreme odziva *task*-a mereno od trenutka pristizanja.
- **Vreme izbacivanja** ili **pristizanja *task*-a** (*arrival time*) - vreme kada je task spreman 
za izvršavanje.
- **Vreme odziva** - reme proteklo od kada je task spreman za izvršavanje do završetka izvršavanja *task*-a.
- **Apsolutni krajnji rok** $d$ - apsolutno vreme do kada izvršenje *task*-a mora biti završeno.

Kod koncepta **cikličnog raspoređivanja** odluke o raspoređivanju se vrše periodično u vremenskim intervalima (na njihovom početku intervala) koji se nazivaju **frejmovi** (*frame* - *minor cycle*). **Glavni ciklus** (*major cycle*) predstavlja minimalni period za izvršavanje svih *task*-ova u kome su zadovoljeni svi vremenski zahtevi i periode svih *task*-ova. Može se koristiti kod fiksnog seta periodičnih taskova.

Veličina frejma/ciklusa mora da zadovolji sledeće zahteve:

- *Major frame* 
    - $\underset{1 \le i \le n}{nzs}(p_i)$ 

- Dužina frejma mora biti dovoljna da se svaki *task* može započeti i završiti svoje izvršavanje u okviru jednog frejma.
    - $f \ge \underset{1 \le i \le n}{max}(e_i)$

- Kako bi se smanjio broj ulaza kod cikličnog raspoređivanja, glavni ciklus treba da bude deljiv sa dužinom frejma (bar jedan $p_i$ treba da bude deljiv sa $f$).
    - $ [p_i/f] - p_i/f_i = 0$

- Kako bi se obezbedilo da se izvršavanje svakog *task*-a završi do *task* *deadline*-a, frejmovi moraju biti kratki tako da između trenutka pojavljivanja i krajnjeg roka za izvršenje *task*-a u najgorem slučaju postojao jedan frejm.
    - $2f - nzd(p_i,f) \le D_i$

***Rate-monotonic*** teorema: Za dati set periodičnih *task*-ova i prioritetni algoritam raspoređivanja, dodeljivanje prioriteta *task*-ovima, tako da *task*-ovi sa kraćim periodama imaju veći prioritet, vodi ka optimalnom algoritmu raspoređivanja.

Teorema o graničnom uslovu primenljivosti *rate-monotonic* algoritma: Svaki set periodičnih *task*-ova je rasporedljiv na procesoru ukoliko iskorišćenost procesora nije veća od $n(2^\frac{1}{n} - 1)$

Prema **EDF algoritmu** *task* koji je spreman za izvršavanje sa najskorijim apsolutnim krajnjim rokom ima najviši prioritet u svakom trenutku vremena.

Teorema o graničnim uslovima primenljivosti EDF algoritma raspoređivanja: Set periodičnih *task*-ova, kod kojih je relativni *deadline* jednak njihovom periodu, može se na izvodljiv način 
rasporediti ako i samo ako je ispunjeno:

$$
\sum_{i=1}^n \frac{e_i}{p_i} \le 1
$$

> [!NOTE]
> EDF algoritam je fleksibilniji i postiže bolje iskorišćenje dok je RM algoritam predvidljiviji. U slučaju kada je sistem preopterećen, RM algoritam je stabilan u prisustvu neispunjenih *deadline*-ova, što je od esencijalne važnosti za RT sistem. Neispunjeni *deadline* kod RM koncepta je vezan za *task* nižeg prioriteta (tj. imamo predvidivo ponašanje sistema u smislu otkaza sistema), dok je kod EDF algoritma teško predvideti koji *task* neće biti izvršen u roku (može biti i *task* visokog prioriteta). RM algoritam zahteva češće raspoređivanje u odnosu na EDF algoritam

Kod ***Least Slack Time*** (*Least Laxity First*) algoritama najveći prioritet ima *task* sa najmanjim parametrom urgentnosti:

$$
L = d - t - e
$$

gde je $d$ - relativni *deadline*, $t$ - trenutno vreme i $e$ - preostalo vreme.

***Multi-Level Feedback Queue*** algoritam podrazumeva postojanje više lista (redova) *task*-ova spremnih za izvršavanja koje su međusobno u nekom prioritetnom redosledu. Svaki od redova može imati implementirane različite mehanizme i vremensku jedinicu raspoređivanja. Uobičajeno redovi sa *task*-ovima višeg prioriteta imaju kraću vremensku jedinicu.

Novo pridošlim *task*-ovima se daje viši prioritet i malo procesorsko vreme. Ukoliko *task* iskoristi raspoloživo vreme bez blokiranja (nije se izvršio), njegov prioritet se smanjuje i njemu se dodeljuje duže procesorsko vreme. *Task*-u koji se izvrši u intervalu kraćem od dodeljenog povećava se prioritet.

## Objekti kernela OS

***Task*** predstavlja nezavisnu nit izvršavanja koja se može nadmetati sa ostalim konkurentnim *task*-ovima za procesorsko vreme. Nakon kreiranja, svakom *task*-u je pridruženo ime, jedinstveni ID, prioritet (sve kao deo TCB-a), stek *task*-a i programska rutina *task*-a. 

Nakon startovanja, kernel kreira sopstveni set sistemskih *task*-ova i dodeljuje im odgovarajuće prioritete iz seta rezervisanih nivoa prioriteta. Npr. ***Idle task*** se kreira prilikom startovanja kernela i dodeljen mu je na najniži prioritet. Obično se izvršava u beskonačnoj petlji i aktivan je kada ne postoji ni jedan drugi *task* spreman za izvršavanje.

Nakon što je kernel inicijalizovan i nakon što je kreirao sve potrebne *task*-ove, kernel skače na predefinisanu ulaznu tačku korisničke aplikacije – ***entry point***.

U svakom trenutku svaki *task* pojedinačno se nalazi u određenom (jednom) stanju iz skupa mogućih stanja:
- ***Ready*** - *task* je spreman za izvršavanje, ali trenutno se izvršava *task* višeg prioriteta.
- ***Running*** - *task* se trenutno izvršava obzirom da je trenutno *task* sa najvišim prioritetom od svih *task*-ova koji su spremni za izvršavanje.
- ***Blocked*** - *task* zahteva resurs koji nije dostupan. U ovom slučaju *task* može čekati do pojave nekog događaja ili odložiti svoje izvršavanje za neko određeno vreme.

Neki komercijalni kerneli, definišu druga stanja, koja često predstavljaju podgrupe nekog od tri osnovna stanja:

- *Pended* - označava *task* koji čeka na resurs da bude oslobođen.
- *Delayed* - *task* čeka istek nekog vremenskog intervala.
- *Suspended* - stanje postoji za namene debagovanja.

Blokiranje *task*-ova se koristi za namene sinhronizacije aktivnosti i komunikacije između *task*-ova, dakle obezbeđuje osnovu za kreiranje *real-time* aplikacija.Prilikom izlaska iz blokiranog stanja, *task* može preći u spremno stanje, ukoliko on nije *task* najvišeg prioriteta, pri čemu se smešta u listu spremnih *task*-ova na odgovarajuću lokaciju. Ukoliko je odblokirani *task* najvišeg prioriteta, on prelazi direktno u stanje izvršavanja.

U sistemske pozive koje omogućavaju **manipulaciju sa *task* objektom** spadaju funkcije:

- Kreiranje i brisanje *task*-a.
- Kontrolne operacije nad *task*-ovima - manipulacija *task*-ovima (promena parametara modela, promene stanja *task*-ova).
- Preuzimanje statusa - preuzimanje informacija vezanih za *task* objekat.

Kao **posledica nepravilnog brisanja *task*-a** može doći do:

- **Gubitka memorije** (*memory leak*) se događa kada je izvršeno dodeljivanje memorije ali ne i njeno oslobađanje.
- **Gubitak resursa** (*resource leak*) se događa kada je izvršena dodela nekog resursa ali ne i njegovo oslobađanje, čime dolazi do gubitka memorije, obzirom da svaki resurs zauzima prostor u memoriji.

Osnovne operacije nad *task*-ovima u smislu ručnog raspoređivanja uključuju:
- *suspended* - operacije za suspendovanje *task*-a
- *resume* - izlazak iz suspendovanog stanja
- *delay* - blokiranje *task*-a za neko vreme
- *restart* - restartovanje *task*-a
- *set priority* - dinamičko postavljanje prioriteta *task*-a
- *preemption lock* - onemogućavanje prioritetnog prekidanja izvršavanja *task*-a
- *preemption unlock* - omogućavanje prioritetnog prekidanja izvršavanja *task*-a

> [!NOTE]
> **Suspendovano stanje** je slično blokiranom stanju u smislu da suspendovan *task* niti je spreman za izvršavanje niti se izvršava. Razlika se ogleda u činjenici da *task* u ovo stanje ne prelazi svojevoljno na osnovu API poziva, već kao posledica izvršavanja nekog sistemskog *task*-a operativnog sistema.

**Operacija restartovanja *task*-a** e korisna tokom procesa debagovanja *task*-a ili za namenu reinicijalizacije *task*-a nakon pojave katastrofalne greške.

### Semafor

**Semafor** (ili *semaphore token*) je objekat kernela koji može biti dodeljen (*acquire*) ili oslobođen (*release*) od strane jednog ili više *task* objekata korisničke aplikacije i koristi se dominantno za namene sinhronizacije pristupa deljenim resursima sistema.

Kada je semafor kreiran, kernel operativnog sistema kreira SCB (*Semaphore Control Block*) što uključuje jedinstven ID broj objekta, pridruženu vrednost semafora i pridruženu listu taskova koji čekaju određeno stanje semafora (*task-waiting* list). 

Svaki semafor može biti dodeljen konačan broj puta, ako je reč o brojačkom semaforu ova vrednost može biti veća od 1. Ako ne postoji dostupan *semaphore token*, task prelazi u blokirano 
stanje ako je izvršen blokirajući poziv za preuzimanje semafora tokena.

> [!IMPORTANT]
> Svi pozivi za dodelom ili oslobađanjem semafora bi trebalo da su dati u formi atomskih operacija.

***Task waiting list*** - Lista sa *task*-ovima koji čekaju na semafor, predstavlja listu svih blokiranih *task*-ova koji čekaju da semafor postane dostupan. Blokirani taskovi se drže u listi *task*-ova koji čekaju u FIFO formatu ili u prioritetnom rasporedu.

Kernel može podržavati više različitih tipova semafora, kao što su:

- Binarni semafori (*binary semaphores*)
- Brojački semafori (*counting semaphores*)
- Semafori za međusobno isključiv pristup (*mutex semaphores*)

**Binarni semafori** mogu imati vrednosti 0 ili 1 (value polje u SCB). Kada je vrednost binarnog semafora 0, smatra se da je semafor nedostupan (ili prazan), dok kada je vrednost semafora 1, smatra se da je semafor dostupan (ili pun). Po kreiranju, vrednost binarnog semafora može biti inicijalizovana na bilo koju vrednost (0 ili 1).

**Brojački semafor** koristi brojač kako bi omogućio da semafor bude dodeljen ili oslobođen više puta. Kada je brojački semafor kreiran, inicijalizovana je i početna vrednost brojača. Tipovi brojačkih semafora prema ograničenoj ili neograničenoj vrednosti brojača semafora.

> [!NOTE]
> Binarni i brojački semafori se tretiraju kao globalni resurs, što podrazumeva da je deljeni resurs između svih *task*-ova, čime je omogućeno da ga bilo koji *task* oslobodi, bez obzira da li mu je prethodno bio ili nije bio dodeljen.

***Mutex* semafori** predstavljaju specijalnu verziju binarnih semafora koji podržavaju osobine vlasništva nad semaforom, rekurzivnog pristupa, zaštite od brisanja *task*-a i jedan ili više protokola koji omogućavaju izbegavanje problema vezanih za pojavu inverzije prioriteta i uzajamnog blokiranja. *Mutex* semafor je inicijalno kreiran u otključanom stanju, kada može biti dodeljen nekom *task*-u. Nakon što je dodeljen, *mutex* semafor prelazi u zaključano stanje.

> [!IMPORTANT]
> Kada je *mutex* u vlasništvu nekog *task*-a, nije moguće da bilo koji drugi *task* izvrši operacije dodele ili oslobađanja *mutex*-a, što je suprotno konceptu binarnih i brojačkih semafora koji su globalni resursi.

**Rekurzivni pristup *mutex*-u** - Mnoge implementacije *mutex* semafora omogućavaju rekurzivno zaključavanje, pri čemu je omogućeno da *task* koji poseduje *mutex* izvrši višestruku dodelu *mutex*-a u zaključanom stanju. Kada je rekurzivni *mutex* prvi put dodeljen, kernel registruje *task* kome je *mutex* dodeljen kao njegovog vlasnika. Prilikom uzastopnih pokušaja, kernel koristi interni brojač pokušaja dodele, koji je pridružen *mutex* semaforu, za beleženje rekurzivnog broj pokušaja dodele *mutex*-a *task*-u, koji je vlasnik *mutex*-a, ili rutinama *task*-a. Kako bi *mutex* bio oslobođen na ispravan način, on mora imati isti broj pokušaja oslobađanja *mutex*-a.

**Zaštita brisanja *task*-a** je izvedena u formi zaključavanja i otključavanja *mutex*-a, obzirom da ako je omogućena ova funkcionalnost *mutex* semafora, *task* sve dok poseduje neki *mutex*, ne može biti obrisan. 

**Inverzija prioriteta** se obično dešava kod loše projektovanih aplikacija. Ova pojava podrazumeva blokiranje *task*-a višeg prioriteta kao posledicu čekanja na resurs koji se koristi od strane *task*-a nižeg prioriteta, čije je izvršavanje prekinuto od strane *task*-a srednjeg 
prioriteta.

**Protokol nasleđivanja prioriteta** (*priority inheritance protocol*) obezbeđuje da je nivo prioriteta *task*-a nižeg prioriteta kome je dodeljen *mutex* povećan na vrednost nivoa prioriteta *task*-a visokog prioriteta koji čeka na oslobađanje *mutex*-a. Nivo prioriteta *task*-a niskog prioriteta se vraća na originalnu vrednost nakon njegovog oslobađanja *mutex*-a.

**Protokol sa najvišim prioritetom** (*ceiling priority protocol*) obezbeđuje da se nivo prioriteta *task*-a kome je *mutex* dodeljen automatski postavlja na najveći nivo od svih mogućih *task*-ova koji mogu zahtevati *mutex* od njegovog prvog dodeljivanja do njegovog oslobađanja.

Uobičajene operacije sa semaforima:

- **Create** - operacija kreiranja semafora
- **Delete** - operacija brisanja semafora
- **Acquire** - zahtev za dodelom semafora
- **Release** - operacija oslobađanja semafora
- **Flush** - operacija deblokiranja svih *task*-ova koji čekaju na dodelu semafora.
- **Show info** - prikaz osnovnih informacija o semaforu.
- **Show blocked *task*-s**  Preuzimanje liste ID *task*-ova koji su blokirani na semaforu.

Tipični zahtev (*acquire*) za dodelom semafora tasku izvodi se u nekom od sledećih oblika:

- Čekanja zauvek - *task* ostaje blokiran dok operacija dodele nije izvršena
- Čekanja u nekom intervalu vremena - *task* ostaje blokiran dok operacija dodele semafora nije izvršena ili dok ne istekne inicijalizovani vremenski interval čekanja. 
- Bez čekanja - *task* pravi poziv za dodelu semafora, ali u slučaju da semafor nije dostupan ne dolazi do blokiranja *task*-a.

### Redovi sa porukama

Kako bi obezbedio efikasan način za razmenu podataka između *task*-ova, kernel operativnog sistema uvodi objekat tipa red sa porukama (*message queues*, *mailboxes*) i servise upravljanje objektom. 

**Red sa porukama** je objekat organizovan oko bafera preko koga *task*-ovi i/ili prekidne rutine razmenjuju i/ili šalju podatke u cilju komunikacije i sinhronizacije svojih aktivnosti.

Komponente objekta reda sa porukama su: 

- Kontrolni blok reda QCB (*Queue Control Block*) koji čuva naziv reda sa porukama, ID broj, dužinu reda, dužinu poruke i pokazivača na karakteristične elemente u redu
- Memorijski bafer
- TWL (*Task Waiting List*) - liste sa jednim ili više *task*-ova koji čekaju na slanje i prijem poruka

Prilikom kreiranja, red sa porukama se nalazi u praznom stanju (*empty state*) kada nema dostupnih poruka u redu. *Task* koji pokuša da primi poruku iz reda sa porukama, za vreme dok je red sa porukama prazan, prelazi u blokirano stanje u STWL. Lista *task*-ova koji čekaju na prijem poruke je organizovana prema FIFO ili prioritetnom rasporedu. Ako je RTWL prazna, i ako u red sa porukama pristigne poruka, red sa porukama prelazi u stanje (*not empty state*). Nakon slanja poruke redu sa porukama, blokirani *task* iz RTWL najvišeg prioriteta izlazi iz blokiranog stanja i briše se iz RTWL. Blokirajući poziv funkcije vraća pokazivač na poruku, i opciono veličinu poruke. U slučaju kada dodatne poruke pristižu u red sa porukama, i ako nema *task*-ova koji čekaju na ove poruke, može doći do situacije da red sa porukama bude pun (*full state*). Svaki *task* koji šalje poruku neće uspeti da završi svoju operaciju, tj. biće blokiran, sve dok neki element reda ne bude oslobođen.

Tipične operacije nad objektom:

- **Create** - operacija kreiranja reda
- **Delete** - operacija brisanja reda

Poruke se **smeštaju** u FIFO redosledu ili LIFO (Last In First Out) redosledu (ako su implementirane “hitne poruke”). Poruke se mogu **slati** redu sa porukama na jedan od tri načina:

- **bez blokiranja** (ISR ili *task* rutine) - ukoliko je red sa porukama već pun, poziv funkcije za slanje poruke vraća grešku.
- **sa blokiranjem na određeno vreme** (samo kod *task* rutina) - Blokirani *task* se smešta u listu *task*-ova koji čekaju i koja se popunjava u FIFO ili prioritetnom rasporedu.
- **sa neoročenim blokiranjem** (samo kod *task* rutina) 

*Task* koji **čeka na poruku** čeka u FIFO ili prioritetnom rasporedu. *Task*-ovi koji **primaju poruku** mogu primenjivati različite politike blokiranja: 
- **bez blokiranja** 
- **sa oročenim intervalom blokiranja**
- **sa neoročenim intervalom blokiranja** 

Poruke je moguće čitati od glave reda sa porukama na dva različita načina:
- **Destruktivno čitanje** - kada *task* uspešno primi poruku, *task* ujedno i vrši uklanjanje poruke iz bafera za skladištenje poruka reda sa porukama
- **Nedestruktivno čitanje** - *task* čita poruku sa vrha reda bez njenog uklanjanja.

Tipični načini upotrebe reda sa porukama u okviru aplikacije: 
- Jednosmerna komunikacija bez potvrde prijema 
- Jednosmerna komunikacija sa indikacijom prijema poruke (sa softverskim *handshaking*-om) 
- Dvosmerna komunikacija (*client-server*, *request-response*) 
- Broadcast komunikacija

### *Pipe* objekat

***Pipe*** je objekat kernela koji omogućava razmenu nestruktuiranih podataka i sinhronizaciju između *task*-ova. Kod standardne implementacije *pipe* predstavlja **jednosmerni kanal** za razmenu podataka (*simplex*). *Pipe* omogućava jednostavni mehanizam za protok podataka, tako da *task* koji čita podatke ostaje blokiran dok je *pipe* prazan, dok *task* koji šalje ili upisuje podatke, ostaje blokiran sve dok je *pipe* pun. Protok podataka kroz pipe je striktno **FIFO tipa**.

*Pipe* objekat se kreira u **praznom stanju**. Nakon kreiranja *pipe* objekta poziv funkcije vraća dva deskriptora kao reference na krajeve *pipe* bafera. Podaci se upisuju preko jednog a čitaju preko drugog deskriptora. Podaci su **nestruktuiranom obliku**, tj. smešteni su u formi **niza bajtova**.

Kernel operativnog sistema kreira i održava informacije vezane za *pipe*-ove u internoj strukturi podataka koja se zove **kontrolni blok *pipe***-a (*Pipe Control Block* - PCB). PCB uobičajeno sadrži:

- memorijski bafer *pipe*-a (alociran od strane operativnog sistema)
- podatak o (maksimalnoj) veličini bafera 
- pokazivače na ulaznu i izlaznu lokaciju iz *pipe*-a (deskriptore) 
- broj bajtova u baferu

Kernel uobičajeno podržava dva tipa *pipe* objekta:

- **Imenovani *pipe*** - poznat kao FIFO *pipe*, koji se pojavljuje u fajl sistemu slično kao što se pojavljuju fajlovi ili I/O uređaji. Svaki *task* ili ISR koji koristi imenovani *pipe*, mu pristupa preko njegovog imena i vrši *read* ili *write* operacije. Koriste se za jednosmernu 
IPC komunikaciju.

- **Neimenovani *pipe*** - ne pojavljuje se u fajl sistemu i referencira se preko deskriptora koje kernel vraća prilikom kreiranja *pipe* objekta.

Tipične operacije nad *pipe* objektom:

- *Pipe* operacija - kreira *pipe* objekat tipa neimenovanog *pipe*-a.
- *Open* operacija - otvara *pipe* objekat kod imenovanog *pipe*-a koji je prethodno kreiran preko (npr. poziva funkcija mknod/mkfifo).
- Close operacija - zatvara i eventualno briše imenovani *pipe* objekat.
- *Flush* operacija - svi podaci se brišu iz *pipe*-a i *pipe* se vraća u prvobitno stanje nakon svog kreiranja
- *Select* operacija - omogućava da se task blokira i čeka na pojavu specificiranog stanja na jednom ili više *pipe*-ova.

> [!IMPORTANT]
> Operacija čitanja je destruktivna operacija, pa se *pipe* objekat ne može koristiti za *broadcast*-ovanje podataka višestrukim *task*-ovima. 

### Indikatori grupe događaja

Neki kerneli podržavaju specijalni registar u okviru TCB (***event register***) ili formu globalnog objekta (***event group***). Bez obzira na implementaciju objekat se sastoji od grupe binarnih indikatora događaja (***binary event flags***). Svaki bit registra se koristi za praćenje pojave specifičnih događaja i može se ili postaviti (***set***) ili obrisati (***clear***). Registri događaja omogućavaju signaliziranje pojave događaja tačno određenom *task* objektu (*event register*) ili se koristiti kao globalni objekt (*event group*).

*Task* može čekati odgovarajuće stanje registra događaja. Čekanje može biti u formi čekanja bilo kog događaja ili tačno određenog događaja i može biti implementirano u formi blokirajućeg ili oročenog blokirajućeg poziva.

Za rad sa registrom događaja *task* može izvršiti poziv dve glavne operacije za **slanje** (*send*) ili **prijem** (*receive*) događaja. *Task* specificira da li želi da čeka, kao i vreme čekanja na prijem željenog događaja ili grupe događaja.

> [!NOTE]
> Pojava uzastopnih događaja preko uzastopnog postavljanja bita indikacije događaja se ne beleži u formi reda.

### Signali

**Signali** predstavljaju formu koja se koristi za signalizaciju događaja između *task* rutina/procesa (mehanizme za IPC) i mehanizam za njihovo asinhrono procesiranje. U osnovi signali se koriste za asinhronu dojavu procesu o nekom događaju koji se odigrao, kao neka **forma softverskog prekida** koji se generiše prilikom pojave nekog događaja. Kada je signal primljen, operativni sistem prekida normalni tok izvršavanja procesa i startuje specifičnu **signalnu rutinu**, ako je prethodno *task* istu instalirao, ili *default* rutinu ako nije.

Nakon pristizanja signala, proces napušta svoj normalni tok izvršavanja i odgovarajuća signalna rutina (*signal routine*, *signal handler* ili *asynchronous signal routine* - ASR) započinje izvršavanje.

> [!WARNING]
> Signalne rutine je potrebno pisati na takav način da ne izazivaju greške u izvršavanju *task* rutina, menjaju globalne promenljive, prekidaju funkcije za dinamičku alokaciju memorije.

U slučaju ako su signali podržani od strane kernela operativnog sistema, kernel kreira i **kontrolni blok signala** kao deo TCB-a.

U opštem slučaju signale je moguće:

- ignorisati (***ignored signals***) - nakon pojave ne prekida izvršavanje *task* rutine
- prihvatiti (***pending signals***) - signali koji su pristigli za vreme dok se vrši procesiranje drugog signala se čuvaju u grupi pristiglih signala
- želeti (***wanted signals***) - signali za koje je *task* spreman
- blokirati (***blocked signals***) - koristi u slučaju ako je potrebno obezbediti da se neki deo *task* rutine (kritična sekcija *task* rutine) zaštiti od prekida izvršavanja.

Tipične operacije sa signalima:

- **Catch** - postavljanje signalne rutine (ili signal)
- **Release** - uklanjanje signalne rutine
- **Send** - slanje signala drugoj *task* rutini (ili *raise*)
- **Ignore** - onemogućavanje isporuke signala
- **Block** - blokiranje isporuke specificiranog signala
- **Unblock** - odblokiranje isporuke specificiranog signala

Za većinu signala je moguće postaviti signalnu rutinu, osim za dva signala za koje to **nije moguće**:

- **KILL** – terminira process
- **STOP/CONTINUE** – suspenduje/nastavlja izvršavanje procesa

### Uslovne promenljive

**Uslovne promenljive** (*conditional variables*) pružaju alternativu za sinhronizaciju *task*-ova. Glavna razlika između *mutex*-a i uslovnih promenljivih je što *mutex* implementira sinhronizaciju preko kontrole pristupa podacima u okviru deljenog resursa, dok uslovne promenljive omogućavaju sinhronizaciju *task*-ova prema sadržaju ili stanju deljenog resursa. Pomoću uslovnih promenljivih *task* može zahtevati pristup resursu koji je u nekom određenom stanju.

Kada *task* ispituje stanje uslovne promenljive, odnosno deljenog resursa, *task* mora imati ekskluzivan pristup uslovnoj promenljivoj, zbog toga se *mutex* uvek koristi uz uslovnu promenljivu.

Upotrebom uslovnih promenljivih, kernel operativnog sistema garantuje *task* rutini da može osloboditi *mutex* i preći u blokirano stanje čekanja u jednoj atomskoj operaciji, što predstavlja suštinu uslovne promenljive.

Operacije nad uslovnom promenljivom:

- **Create** - kreiranje i inicijalizacija uslovne promenljive
- **Wait** - čekanje na uslovnu promenljivu
- **Signal** - signaliziranje uslovnoj promenljivoj o zadovoljenju uslova
- **Broadcast** - signaliziranje svim *task*-ovima koji čekaju na prisustvo uslova

> [!IMPORTANT]
> **Dve atomske operacije**: za oslobađanje mutex-a i čekanje na ispunjenje uslova (*wait* operacija), kao i odblokiranje taska koji čeka na uslov i dodelu mutex-a njemu (*signal* operacija).

## Sinhronizacija i komunikacija

Pod pojmom sinhronizacije podrazumevaju se dve kategorije:

- **Sinhronizacija pristupa resursu** (*resource synchronization*) - pouzdan pristup deljenom resursu bez narušavanja integriteta resursa.
- **Sinhronizacija aktivnosti** (*activity synchronization*) - signaliziranje da je izvršavanje *task* rutina došlo do određenog stanja.

**Kritična sekcija koda** podrazumeva deo koda koji pristupa deljenom resursu. **Međusobno isključenje pristupa** podrazumeva da samo jedna *task* rutina u jednom trenutku može pristupiti deljenom resursu.

- ***Locking* metode** uključuju upotrebu *mutex* semafora (*mutex locks*), onemogućavanja prekida (*interrupt locks*) i onemogućavanja prioritetnog raspoređivanja (*preemption locks*).

- ***Mutex locks*** - Task #1 i Task #2 pristupaju deljenoj memoriju preko *mutex* semafora. Svaki *task* mora izvršiti poziv za dodelu *mutex*-a pre pristupa deljenom resursu. Nakon pristupa, *task* rutine oslobađaju *mutex*.

- ***Interrupt locks*** - ISR vrši upis podataka, dok *task* rutina vrši čitanje i procesiranje podataka. *Task* rutine koristi onemogućavanje prekida kako bi onemogućila ISR da je prekine prilikom izvršavanja.

- ***Preemption locks*** - Svaka *task* rutina pre pristupa deljenom resursu treba da onemogući prioritetno raspoređivanje. Sprečava se promena toka izvršavanja.

Neki od **koncepata sinhronizacije** izvršavanja *task* rutina su: 
- Sinhronizacija preko barijere 
- *Rendezvous synchronization*

**Sinhronizacija preko barijere** sastoji se od tri osnovne operacije: 
- *Task* najavljuje svoj dolazak na barijeru.
- *Task* čeka druge *task*-ove da pristignu na barijeru.
- *Task* prima obaveštenje kada treba da nastavi izvršavanje.

***2-way rendezvous synchronization*** - Prema ovom konceptu, oba binarna semafora se kreiraju u nedostupnom stanju. Task 1 je blokiran na Semaforu 1, dok je Task 2 blokiran na Semaforu 2. Praktično kontrolu izvršavanja *task*-a vrši druga *task* rutina preko upravljanja stanjem semafora na kome se *task* blokira. Task 1, se izvršava i najpre oslobađa Semafor 2, nakon čega se blokira prilikom preuzimanja Semafora 1. Nakon toga dolazi do promene konteksta kada se izvršava Task 2, koja slično vrši oslobađanje Semafora 1, nakon čega se blokira prilikom preuzimanja Semafora 2.

**Komunikacija** između *task* rutina podrazumeva međusobno prosleđivanje informacija u cilju koordiniranja izvršavanja ovih *task* rutina.

U slučaju kada komunikacija uključuje jednosmerni prenos podataka, onda je reč o **labavo povezanoj komunikaciji** (*loosely coupled communication*), kada prenos podataka ne podrazumeva indikaciju prijema.

Suprotno od labavo povezane komunikacije, primer **čvrsto povezane komunikacije** (*tightly coupled communication*), podrazumeva dvosmerni prenos podataka. Task koji vrši slanje podataka, čeka na odgovor kako bi nastavio slanje podataka ili se potvrda o prijemu poruke šalje asinhrono u odnosu na prijem poruke.

***Daemon task*** - U opštem slučaju pojam *daemon task*-a vezan je za *task*-ove koji se izvršavaju u pozadini, bez direktne kontrole korisnika. Tipični primeri *daemon task*-ova su *task* rutine koje vrše obradu sistemskih logova ili sistemskih poruka.

Uobičajeni problemi koji se javljaju kod aplikacija koje rade u realnom vremenu nastaju kao posledica pristupa deljenim resursima sistema i sinhronizacije aktivnosti i uključuju pojavu: 

- uzajamnog blokiranja izvršavanja (***deadlock***) 
- problema inverzije prioriteta (***priority inversion***)

***Deadlock*** predstavlja situaciju u koji više konkurentnih *thread*-ova izvršavanja ostaju trajno blokirana u sistemu kao posledica zahteva za resursom koji nikada ne može biti zadovoljen. Najčešći uzroci pojave *deadlock*-a:

- Međusobno isključiv pristup resursu - pristup resursu je omogućen od strane samo jedne *task* rutine u jednom trenutku.

- Pristup sa onemogućenim raspoređivanjem - resurs je zaštićen od promene konteksta, čime se može osloboditi samo od strane *task* rutine kojoj je trenutno dodeljen.

- Držanja resursa i čekanja na drugi resurs - nakon što mu je neki resurs dodeljen, *task* rutina čeka na dodelu narednog resursa.

- Kružnog čekanja - Postojanje lanca od dva ili više *task* rutina koje drže resurs koji je zahtevan od prethodne *task* rutine u lancu i zahtevaju resurs koji je dodeljen narednoj *task* rutini.

Detekcija *deadlock*-a podrazumeva periodično izvršavanje algoritma detekcije od strane RTOS-a, pri čemu se ispituje trenutno stanje resursa sistema i neispunjenih zahteva za dodelom resursa, čime se utvrđuje da li na sistemu postoji problem u formi *deadlock*-a.

- **Pojam stabilnog *deadlock*-a** - za izlazak iz stabilnog *deadlock*-a neophodna je intervencija RTOS-a. 
- **Pojam privremenog *deadlock*-a** - automatski se otklanjanja problem *deadlock*-a nakon isteka nekog vremena.

Prevencija pojave *deadlock*-a:

- Eliminacija stanja čekanja nakon što je neki resurs već dodeljen *task* rutini - *Task* zahteva sve resurse koji su mu potrebni za izvršavanje, pre početka svog izvršavanja.

- Eliminacija onemogućavanja raspoređivanja - Onemogućena je progresija izvršavanja *task*-a, samim tim i resurs ostaje blokiran neoročeno vreme.

- Eliminacija držanja i čekanja na drugi resurs - *Task* kome je dodeljen neki resurs, nakon zahteva za dodelom nedostupnog resursa, treba najpre da oslobodi prethodno zauzeti resurs i da zatim ponovo pošalje zahtev za dodelom svih resursa koji su potrebni za njegovo izvršavanje

- Onemogućavanje cikličnog čekanja za dodelom resursa - Ukoliko je *task* rutini dodeljen resurs Ri onda u narednoj dodeli istoj *task* rutini može biti dodeljen samo resurs Rj pri čemu je j>i (uvodi se hijerarhija među resursima).

**Inverzija prioriteta** se sigurno javlja kod većine koncepta  sinhronizacije aktivnosti ili pristupa resursu i nije neželjena pojava. Trajanje intervala inverzije prioriteta zavisi od trajanja izvršavanja taskova srednjeg prioriteta koji nisu sinhronizovani sa izvršavanjem LP_taska i HP_taska.

- **Protokol nasleđivanja prioriteta** - Trajanje intervala inverzije prioriteta ne zavisi od trajanja izvršavanja *task*-ova srednjeg prioriteta koji mogu biti spremni za izvršavanje na sistemu.

- **Protokol sa najvišim prioritetom** - Kada je neki resurs dodeljen nekom *task*-u, njegov prioritet se automatski postavlja na vrednost prioriteta resursa koji mu je dodeljen. Protokol onemogućava pojavu *deadlock*-a.

## Servisi RTOS-a

Dodatni servisi operativnog sistema nalaze van kernela, čime se postiže mogućnost konfigurabilnosti i skalabilnosti sistema. Cilj ovakvog pristupa je da se u okviru **mikro-kernela** implementiraju osnovni servisi kernela na osnovu kojih je moguće 
razviti druge servise kernela kao nezavisne module.

Osnovni servisi mikrokernela:

- Servis kao podrška za rad sa task objektima 
- Raspoređivanje taskova, algoritmi raspoređivanja 
- Objekti za sinhronizaciju aktivnosti i pristupa resursima 
- Procesiranje izuzetaka i prekida 
- Upravljanje memorijom

Uobičajeni sastavni blokovi RTOS-a, koji obezbeđuju dodatne servise, su:

- *TCP/IP Protocol Stack*
- *File system*
- *Remote procedure call* (RPC) 
- *Command shell* 
- *Target debug agent*

***TCP/IP Protocol Stack*** - Skup mrežnih protokola obezbeđuje sistemske servise za namenske aplikacije koje se izvršavaju u mrežnom okruženju. TCP/IP protokol stek obezbeđuje servise za transport za poznate protokole višeg nivoa, kao što su SNMP (*Simple Network Management Protokol*), NFS (*Network File System*), *Telnet*, i druge posebne protokole koji se koriste od strane korisničke aplikacije.

Transportni servisi mogu biti tipa pouzdane komunikacije preko TCP protokola ili nepouzdane komunikacije preko UDP protokola. TCP/IP protokol stek može funkcionisati preko različitih tipova fizičkih konekcija i mreža, uključujući *Ethernet*, *Frame Relay*, ATM i ISDN mreže preko upotrebe različitih protokola za enkapsuliranje, uključujući *Point-to-Point Protocol* (PPP).

***File System*** - Predstavlja set apstraktnih tipova podataka koji su implementirani za namene skladištenja, hijerarhijske organizacije, manipulacije, navigacije, pristupa i dobavljanja podataka. Fajl sistem komponenta obezbeđuje da se uređaj za skladištenje podataka bude struktuiran prema nekom od **podržanih formata** za upis i čitanje podataka.

Fajl sistem je odgovoran za organizaciju **sektora** (niz blokova određene dužine) u fajlove i direktorijume, vodeći računa o tome koji sektor pripada kojem fajlu i koji sektori nisu iskorišćeni. Većina sistema adresira podatke u fiksnim veličinama koji se nazivaju **klasteri** ili **blokovi** (sadrže određeni broj sektora). 

***Network File System*** (NFS) je protokol omogućava lokalnoj aplikaciji pristup fajlovima na dislociranom sistemu kao da se nalaze na  lokalnom računaru.

Arhitektura fajl sistema:

- **Logički fajl sistem** - Obezbeđuje interfejse prema aplikaciji koji uključuju pristup fajlovima, operacije za rad sa direktorijumima, zaštitu i prava pristupa.
- **Osnovni fajl sistem** - Rad sa drajverima uređaja, manipulacija blokovima podataka koji se razmenjuju sa fizičkim periferijskim uređajima, vođenje računa o smeštanju blokova u memoriju i baferisanju u sistemskoj memoriji. 
- **Drajveri uređaja** - Direktna komunikacija i I/O operacije nad periferijskim uređajima. Optimizacija pristupa uređajima i procesiranje zahteva za I/O operacijom.

***Remote Procedure Call*** (RPC) - obezbeđuje mehanizam za poziv procedure čiji je programski kod u drugom adresnom prostoru, odnosno van adresnog prostora *target* sistema. **RPC server** obezbeđuje servise dislociranim sistemima za izvršavanje različitih procedura koje je moguće pozvati iz drugog adresnog prostora. Udaljeni **RPC klijent** može pozvati ove  procedure preko mrežne konekcije  upotrebom RPC protokola.

Za klijent aplikaciju poziv udaljene  procedure *(procedure stub*) ima isti  karakter kao i poziv lokalne procedure. RPC klijent i server se mogu izvršavati na različitim operativnim sistemima i različitim tipovima hardvera. RPC podrazumeva request/response mehanizam razmene poruka i jedinstvenu metodu prezentacije podataka (npr. *External Data Representation* - XDR format).

***Command Shell*** - predstavlja komponentu koja  obezbeđuje interfejs između krajnjeg korisnika i RTOS-a. Korisnik izvršava različite komande koje komandni šel interpretira i izvršava preko poziva RTOS rutina koje mogu biti u formi dinamički kreiranih *task*-ova ili direktnih poziva funkcija operativnog sistema ili sistemskih poziva.

***Target debug agent*** - podrška za debagovanje aplikacije. Podrška se sastoji u implementiranim komandama za debagovanje, preko kojih se postavljaju *break points*, ispituje i postavlja sadržaj lokacija sistemske memorije, registara, objekata RTOS-a kao što su *task*-ovi, semafori i redovi sa porukama. ***Host debager***, dat u formi GUI-a interfejsa može pružati podršku za debagovanje izvornog koda aplikacije preko komunikacije sa *target debug agent*-om.

**Izuzeci** (*exceptions*) i **prekidi** (*interrupts*) su deo mehanizma koji je podržan kod većine namenskih procesora u formi podrške za prekidanje normalnog toka izvršavanja programa i spadaju u jedan od elementarnih servisa koji su podržani od strane kernela RTOS-a. 

Izuzeci mogu biti:

- **Sinhroni** - Izuzeci koji su uzrokovani pojavom internih događaja u okviru CPU, kao posledica izvršavanja procesorske instrukcije.
- **Asinhroni** - Izuzeci vezani za spoljašnje događaje koji ne predstavljaju posledicu izvršavanja procesorske instrukcije.

**Prekidi** ili **spoljni prekidi** su **asinhroni izuzeci** izazvani događajem koji je generisan od strane spoljašnjeg hardverskog uređaja, i predstavljaju samo jednu klasu izuzetaka.

Klasifikacija opštih izuzetaka:

- **Asinhroni nemaskirajući izuzeci** - Hardverski reset i NMI (*Non-Maskable Interrupt*).

- **Asinhroni maskirajući izuzeci** - Svi ostali asinhroni izuzeci koje je moguće maskirati.

- **Sinhroni precizni** - Izuzeci kod kojih je moguće tačno odrediti instrukciju čije je izvršavanje dovelo do generisanja izuzetka.

- **Sinhroni neprecizni** - Izuzeci koji se koriste kod naprednih tehnika u cilju povećavanja performansi procesora (protočna obrada, mehanizam keširanja, prediktivno izvršavanje instrukcija)  ili izuzeci za koje nije moguće tačno odrediti instrukciju koja je dovela do generisanja izuzetka.

Rutine za procesiranje izuzetaka ESR (*Exception Service Routine*) i prekidne rutine ISR (*Interrupt Service Routine*) moraju biti postavljene na sistemu pre nego što dođe do pojave prekida ili izuzetka. Proces postavljanja ESR i ISR podrazumeva poznavanje tabele izuzetaka i prekida (**general exception table**). Obzirom da svaki ulaz u tabeli ima pridruženu vektorsku adresu ulaza, ova tabela se naziva i **vektorska tabela prekida**. Proces postavljanja odgovarajuće servisne rutine predstavlja postupak zamene adrese iz tabele prekida sa adresom početka *handler* rutine.

Pre procesiranja izuzetaka i prekida snimaju se informacije o stanju procesora (PC i SR registara, itd.) u sistemskoj memoriji. Uobičajeno je da se sve informacije čuvaju na steku. Pristup prilikom pokretanja servisne rutine može podrazumevati alociranje bloka memorije (*exception frame* koji ima formu privatnog steka servisne rutine) od strane ESR ili ISR. Servisna rutina snima vrednost registara, uključujući i prethodno aktivnog pokazivača steka, adrese povratka, u okviru *exception frame*-a.

Opšta pravila za arhitekture gde je omogućeno prekidanje izvršavanja servisnih rutina:

- ISR treba da maskira sve prekide ukoliko je potrebno da izvrši deo koda u formi atomske operacije.

- ISR treba da izbegava pozive *non-reentrant* funkcija kao što su `malloc` ili `printf`, obzirom da task rutine mogu biti prekinute u sred poziva neke od ovakvih funkcija, sto dovodi do katastrofalnih posledica.

- ISR ne sme izvršiti bilo kakvi blokirajući poziv, obzirom da može doći do zaustavljanja rada celog sistema. 

- Preporučljivo je da veći deo ISR procesiranja bude realizovan u formi pozadinske task  rutine koja ne bi imala visok prioritet.

**I/O operacije** - kombinacija I/O uređaja, pridruženih drajvera i I/O podsistem predstavljaju ukupni I/O sistem u namenskom okruženju. Uloga I/O podsistema je da sakrije informacije specifične za uređaj od kernela OS i od razvojnog programera i da obezbedi jedinstven pristupni metod svim periferijskim I/O uređajima na sistemu.

I/O uređaj može biti mapiran na dva načina:

- **Port mapiran** - uređaju se pristupa preko broja porta i specijalnih ulaznih i izlaznih operacija.

-  **Memorijski mapiran** - adresa uređaja je deo sistemskog memorijskog prostora kojima se pristupa preko uobičajenih instrukcija koje vrše prenos podataka između registara procesora i memorijskih lokacija ili između dve memorijske lokacije.

Klasifikacija I/O uređaj:

- **Karakter mod uređaji** - Uređaji koji rade u **karakter modu** omogućavaju nestruktuirani transfer podataka. Prenos podataka je uobičajeno izveden u serijskom obliku, u formi niza bajtova.

- **Blok mod uređaji** - Prenose podatke u formi bloka u jedinici vremena ili po jednom prenosu podataka.  Ovi uređaji mogu uključiti neki protokol za prenos, pa je za njih karakteristična i dodatno procesiranje koje je podrazumevano kod svake operacije čitanja ili upisa.

Set API funkcija je specifičan za svaki drajver, što označava da je aplikaciju koja koristi specifičan set API funkcija **teško portovati na drugi sistem**. Kako bi obezbedili smanjenje zavisnosti upotrebe drajvera od implementacije samog uređaja, namenski sistemi često sadrže **I/O podsistem**. I/O podsistem definiše standardni set funkcija namenjenih za I/O operacije kako bi prikrio specifičnosti uređaja od aplikacije.

Uobičajene I/O funkcije:

- **Create** - Kreira virtuelnu instancu I/O uređaja.
- **Destroy** - Briše virtuelnu instancu I/O uređaja.
- **Open** - Priprema I/O uređaj za upotrebu.
- **Close** - Naznačava uređaju da njegovi servisi nisu više potrebni, čime se iniciraju dodatne operacije..
- **Read** - Čitanje podataka iz I/O uređaja.
- **Write** - Upis podataka u I/O uređaj.
- **Ioctl** - Slanje kontrolnih komandi I/O uređaju i njegovom drajveru.

I/O podsistem uobičajeno održava jedinstvenu I/O **tabelu drajvera** u kojoj su **mapirane funkcije** iz uniformnog seta funkcija I/O podsistema u odgovarajuće funkcije drajvera. Drajver se može instalirati ili ukloniti pozivom uslužnih funkcija I/O sistema. Instaliranje drajvera kreira ulaz u tabeli drajvera.

Pozivom *create* funkcije kreira se **virtuelna instanca uređaja**. Referenca na novo kreirani ulaz u **tabeli uređaja** se vraća nakon izvršenja poziva *create* funkcije. Svaki ulaz u tabeli uređaja čuva generičke informacije (jedinstveno ime i referencu na drajver uređaja) kao i informacije specifične za datu instancu (drajver je jedini entitet u sistemu koji pristupa ovom bloku memorije i interpretira podatke koji se u njemu nalaze).

## Tajmeri i servisi tajmera

**Hardverski tajmeri** (*hard timers*) direktno generišu prekid nakon isteka intervala, i kao takvi se koriste kod aplikacije koje zahtevaju preciznost i predvidive performanse. **Softverski tajmeri** (*soft timers*) generišu softverske događaje i kao takvi se primenjuju kod sistema gde nije striktno zahtevana velika preciznost/rezolucija generisanja vremenskih intervala.

***Real-time clock*** (RTC) se koristi kod mnogih namenskih sistema za merenje vremena i praćenje datuma. RTC obezbeđujući održavanje podataka vezanih za vreme i datum bez obzira da li je sistem pod napajanjem.

Posao **sistemskog sata** je identičan funkcijama RTC-a obzirom da prati ili trenutno vreme ili vreme proteklo od podizanja sistema. Početna vrednost sistemskog sata je uobičajeno preuzeta od RTC prilikom startovanja sistema ili postavljena od strane korisnika. Razlika u odnosu na RTC se odnosi na činjenicu da sistemski sat programabilni interval tajmer (PIT).

**Programabilni interval tajmer** (*Programmable Interval Timer* - PIT) ili poznat kao tajmerski čip/modul, je projektovan da obavlja funkcije brojanja događaja, indikacije proteklog vremena, generisanje periodičnih događaja, ili za neke druge primene.

Karakteristični pojam kod PIT-a je **brzina generisanja prekida** (*timer interrupt rate*), kao broj generisanih prekida u jednoj sekundi. Preko pristupa kontrolnim registrima tajmera podešava se interval generisanja prekida, automatsko učitavanje vrednosti brojača tajmera i sl.

Pojam ***timer tick*** predstavlja  vreme između dva uzastopna generisanja prekida.

Deo inicijalizacije PIT-a uključuje i postavljanje ISR tajmera koja se poziva nakon generisanja prekida od strane tajmera. Uobičajene funkcije ISR tajmera su:

- Održavanje sistemskog vremena, što uključuje održavanje apsolutnog vremena (datuma i vremena) i poteklog vremena od uključenja sistema, što se pamti u formi broja *tick*-ova.

- Poziv odgovarajuće funkcije kernela operativnog sistema, kako bi se kernel obavestio da je preprogramirani interval istekao.
  
- Prihvatanje prekida, reinicijalizacija kontrolnih registara i povratak iz prekidne rutine.

- Obaveštavanje modula koji upravlja softverskim tajmerima.

Funkcije implementirane od strane softverskog tajmer modula uključuju sledeće operacije:

- Omogućavanje aplikaciji da startuje tajmer.
- Omogućavanje aplikaciji da zaustavi tajmer.
- Interno održavanje tajmera različitih aplikacija.

***Timing wheel*** predstavlja konstrukciju realizovanu preko niza fiksne dužine, pri čemu svaki slot predstavlja jedinicu vremena u skladu sa preciznosti modula softverskog tajmera. Svaki naredni slot označava da je protekao još jedan interval između generisanja dva *tick*-a. Kao dodatak, u svakom slotu se nalazi dvostruko ulančana lista funkcija koje se pozivaju nakon što istekne definisani vremenski interval. Ove funkcije se nazivaju **timeout event handlers** ili ***callback* funkcije**. 

> [!NOTE]
> ***Callback* mehanizam** poziva funkcije je model procesiranja događaja, pri čemu se funkciji koja identifikuje događaj prosleđuje pokazivač na *callback* funkciju.

Nakon pojave *tick*-a pokazivač slota (*clock dial*) se inkrementira za jednu poziciju, pri čemu prelazi na početni slot, ukoliko je pre pojave *tick*-a pokazivao na poslednju poziciju u nizu. Prilikom postavljanja novog soft tajmera, trenutni položaj pokazivača slota se koristi za određivanje pozicije postavljanja *event handler*-a.

Mnogi RTOS obezbeđuju set operacija za rad sa tajmerima preko definisanog API seta. Ove operacije se mogu kategorisati u tri grupe:

- Grupa 1 - obezbeđuje *low-level* operacije sa hardverom (sys_timer_setrate, sys_timer_enable)
- Grupa 2 - obezbeđuje servise za rad sa softverskim tajmerom (timer_create, timer_delete, timer_start)
- Grupa 3 - obezbeđuje operacije za rad sa real-time i sistemskim satom (clock_get_time, clock_set_time)
