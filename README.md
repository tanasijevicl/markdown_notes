# Operativni sistemi 1 - notes

## Uvod u operativne sisteme

### Pojam i funkcije operativnog sistema

**Operativni sistem** je program (softver) koji omogućava izvršavanje korisničkih programa na računaru i služi kao posrednik između tih programa i računarskog hardvera, pružajući usluge tim programima.

Operativni sistem se može opisati i kao skup rutina koje obavljaju operacije sa hardverskim uređajima računara, koje se nalaze u memoriji računara i koje se mogu koristiti kao usluge (te usluge programi, koji se izvršavaju na tom računaru, pozivaju kao tzv. **sistemske pozive**).

Tradicionalno shvatanje osnovnih komponenata operativnog sistema:

- **Jezgro/kernel** - deo operativnog sistema koji je uvek učitan u operativnu memoriju sistema ili se u nju učitava pri uključivanju računara i tu ostaje stalno do isključenja, izvršava osnovne funkcije operativnog sistema i pruža usluge programima koji se izvršavaju na računaru

- **Sistemski programi** - programi koji se izvršavaju kao svi ostali, samo što se isporučuju kao sastavni deo operativnog sistema, jer obavljaju neke opšte radnje

- **Korisnički interfejs** - deo za interakciju sa korisnikom

Korisnički interfejsi:

- **Interpreter komandne linije (*command line interpreter*, CLI)** - drugačije konzola, sistemski program (školjka) ili deo kernela koji intereaguje sa korisnikom samo pomoću tastature i ekrana

- **Grafički korisnički interfejs (*graphical user interface*, GUI)** - moderniji interfejs (rasterski ekran, miš, radna površina...)

## Osnovni pojmovi

**Sistemski poziv** (*system call*) je metod kojim program koji se izvršava na nekom OS-u traži određenu uslugu od tog OS-a. 

Skup dostupnih bibliotečnih potprograma koji vrše sistemske pozive na nekom OS-u čini **aplikativni programski interfejs** (*application programming interface*, API) datog OS-a na datom programskom jeziku. Implementacija tih potprograma unutar biblioteke sadrži instrukcije koje vrše sistemski poziv na mašinskom jeziku, urađeno na način kako dati OS to zahteva - **interfejs sistemskih poziva** (*system call interface*).

**Proces** (*process*) je jedno izvršavanje nekog programa na računaru, koje potencijalno teče uporedo sa drugim takvim izvršavanjima istog ili drugih programa.

**Program** je statički zapis, specifikacija onoga što računar treba da uradi. Jedna aktivacija programa predstavlja proces. Nad istim programom može se pokrenuti više procesa, više nezavisnih izvršavanja, svako sa svojim podacima.

Računarski sistemi mogu biti **monoprogramski** ili **multiprogramski**, dok operativni sistemi mogu da budu **monoprocesni** ili **multiprocesni**.

Karakteristično ponašanje svakog programa, smenjuju se dve faze:

- **CPU burst** (nalet izvršavanja na procesoru) - sekvenca instrukcija koje rade samo sa registrima procesora i operativnom memorijom

- **I/O operation** (ulazno-izlazna operacija) - proces traži sistemsku uslugu, tj. ulazno-izlaznu operaciju

Koncept uporednog izvršavanja procesa, pri čemu se procesor vremenski multipleksira između različitih procesa naziva se **multiprogramiranje**.

**Fajl** (*file*) predstavlja univerzalan, jednoobrazan, apstraktan logički koncept za smeštanje podataka i programa na najrazličitijim uređajima. Pristup do fajla je jednoobrazan i obavlja se kroz standardizovan API sistemskih poziva, dok OS sakriva sve raznolikosti i promenljivosti uređaja na kojima su ti podaci smešteni i načina na koji im se pristupa.

### Vrste računarskih i operativnih sistema

Dve fundamentalne koncepcije (hardverske) arhitekture računarskih sistema sa više procesora:

- **Multiprocesorski sistem** - računarski sistem sa više procesora koji imaju zajedničku (deljenu) operativnu memoriju
  
- **Distribuirani sistem** - sistem sa više procesora koji nemaju zajedničku operativnu memoriju, a koji su povezani komunikacionom mrežom preko koje mogu razmenjivati poruke 

Multiprocesorski sistem na hardverskom nivou može biti:

- simetričan - svi procesori opšte namene su jednaki, imaju isto vreme pristupa operativnoj memoriji

- asimetričan - neki procesori su specijalizovani za posebne namene ili imaju različito vreme pristupa memoriji

OS za multiprocesorski sistem može biti:

- simetričan - svi procesori su ravnopravni, u smislu da svi mogu izvršavati kod kernela

- asimetričan - jedan procesor je master i on izvršava raspoređivanje procesa na druge procesore, kao i kernel kod za ostale sistemske usluge; ostali procesori su slave i samo izvršavaju kod korisničkih procesa u skladu sa onim što im procesor dodeli

**Distribuirani operativni sistem** (*distributed OS*) je operativni sistem koji na skupu umreženih računara, tzv. klasteru (*cluster*), stvara utisak jedinstvenog prostora računarskih resursa, odnosno jedinstvenog "virtuelnog računara" i sakriva postojanje različitih računara.

**Serverski računar** je računar namenjen za opsluživanje zahteva koji stižu komunikacionim protokolima preko računarske mreže sa udaljenih računara (klijenata).

**Sistemi u oblaku (*cloud*)** su distribuirani sistemi sa mnogo povezanih serverskih računara u jednom računarskom centru (*data center*) ili regionalno ili globalno raspoređenim računarskim centrima koji obezbeđuju različite usluge korisnicima.

**Ugrađen (*embedded*) sistem** je sistem koji služi za nadzor i upravljanje određenog većeg inženjerskog (hardverskog) okruženja i koji ispunjava svoj cilj obradom informacija, ali pri čemu obrada informacija jeste samo sredstvo, a ne njegov primaran cilj.

Veliki deo ovakvih sistema spada u kategoriju tzv. **sistema za rad u realnom vremenu** (*real-time system*, RT) - sistem koji obrađuje informacije i čije korektno funkcionisanje ne zavisi samo od logičke korektnosti rezultata, nego i od njihove pravovremenosti.

Kategorije RT sistema:

- **"tvrdi" (*hard*)** - sistem za koji je apsolutni imperativ da odziv stigne u zadatom vremenskom roku (*deadline*)

- **"meki" (*soft*)** - sistem kod kojeg je vremenski rok važan i treba da bude poštovan ali se povremeno može i prekoračiti

## Upravljanje memorijom

### Adresiranje memorije

**Operativna memorija** (*operating memory*, OM) je linearno uređen skup ćelija sa pridruženim adresama iz skupa $0..2^{n-1}$, gde je n širina adrese u bitima (najčešće 32 ili 64).

**Asembler (assembly)** je program koji prevodi sadržaj ulaznog, tekstualnog fajla sa kodom na simboličkom mašinskom jeziku u ulazni fajl sa binarnim zapisom mašinskih instrukcija i podataka.

**Direktiva** je linija asemblerskog teksta koja ne sadrži ni jednu instrukciju, već neku drugu specifikaciju ili uputstvo asembleru:

- **def** -  definiše simboličku konstantu, kojoj se pridružuje vrednost konstantnog izraza navedenog u direktivi (`mask def 0x80`)

- **labela** - identifikator (simbol) pridružen jednoj liniji asemblerskog koda, tj. svakoj labeli se pridružuje vrednost tekuće adrese te linije  

- **org** - eksplicitno podešava tekuću adresu linije, tj. uzrokuje promenu adrese od koje se nastavlja (ili započinje) dalje generisanje koda 

- **start** - označava adresu početne instrukcije programa, ovu informaciju koristi OS kada pokreće proces nad ovim programom

- **db|dw|dd** - direktive za definisanje podataka, za svaki navedeni specifikator jednog podatka, odvaja se prostor u generisanom binarnom zapisu za smeštanje jednog podatka navedenog tipa (bajt, dva bajta, ...), na tekućoj adresi, i u taj prostor upisuje binarni zapis vrednosti inicijalizatora koji je zadat konstantnim izrazom, tekuća adresa se uvećava za veličinu alociranih podataka (label: db|dw|dd data-spec,...)

Konstante koje se koriste u programu kao operandi operacija u mašinskim instrukcijama koriste se kao operandi specifikovani **neposrednim načinom adresiranja** (*immediate address mode*). Operand je binarni sadržaj u odgovarajućem polju same instrukcije (`#constant-expression`).

Kod **registarskog direktnog adresiranja** (*register direct address mode*) operand je u registru koji je specifikovan u odgovarajućem polju instrukcije.

Za indirektan pristup preko pokazivača koristi se **registarsko indirektno adresiranje** (*register indirect address mode*). Operand je u memoriji na lokaciji čija je adresa zadata vrednošću registra koji je specifikovan u određenom polju instrukcije.

Kod **registarskog indirektnog adresiranja sa pomerajem** (*register indirect address mode with displacement*) operand je u memoriji na lokaciji čija se adresa dobija sabiranjem sadržaja registra specifikovanog u instrukciji i neposredne konstante definisane u instrukciji.

Ako statički podatak programa inicijalizovan konstantnim izrazom, tj. izrazom čija se vrednost može izračunati za vreme za prevođenja, onda prevodilac generiše binarni zapis te inicijalne vrednosti u prostoru alociranom za taj podatak. 

Pošto se statički alocira za vreme prevođenja, prevodilac poznaje njegovu adresu, pa se pristup do ovih podataka može izvršiti **memorijskim direktnim adresiranjem** (*memory direct address mode*). Operand je u memoriji, na lokaciji čija je adresa zadata u samoj instrukciji.

**Implementacija steka** na nivou arhitekture procesora:

- stek se alocira u memoriji, a na vrh steka može ukazivati vrednost nekog od programski dostupnih registara procesora (*stack pointer*)

- stek može rasti ka višim ili nižim adresama memorije

- vrednost registra može da ukazuje na poslednju zauzetu ili prvu slobodnu lokaciju steka

**Instrukcije potprograma** moraju da adresiraju lokalne podatke relativnim u odnosu na vrh steka, pri čemu su pomeraji poznati i konstantni za dati lokalni podatak i datu poziciju unutar koda potprograma.

**Instrukcije skoka** mogu da adresiraju odredišnu instrukciju **memorijski direktnim adresiranjem**, adresa odredišne instrukcije je data u odgovarajućem polju same instrukcije.

Takođe instrukcije skoka mogu da koriste **relativno**, tj. registarsko indirektno adresiranje sa pomerajem u odnosu na vrednost PC tokom izvršavanja ove instrukcije. Odredište skoka izračunava se kao zbir trenutne vrednosti PC i pomeraja iz instrukcije.

**Prevodilac (*compiler*)** je program koji prevodi tekstualni zapis izvornog programa na višem programskom jeziku u binarni, mašinski zapis. 

Kada prevodilac prevodi jedan fajl sa izvornim kodom (.cpp), prevodilac će generisati jedan fajl sa prevedenim kodom, fajl sa tzv. objektnim kodom (*object file*, .obj ili .o). Fajl sa izvornim kodom sastoji se isključivo od deklaracija tipova (uključujući i klase), funkcija, objekata i drugog. **Deklaracija** je iskaz koji uvodi identifikator programa. Svako ime (identifikator) koje se koristi u programu mora najpre biti deklarisano, u suprotnom će prevodilac prijaviti grešku u prevođenju.

Prevodilac najpre učitane znakove grupiše u veće celine, tzv. leksičke elemente ili lekseme ili žetone (*tokens*). Ova faza prevođenja naziva se **leksička analiza** (*lexical analysis*).

Prevodilac tokom prevođenja prepoznaje veće jezičke celine (rečenice) na osnovu gramatike jezika. Ova faza prevođenja se naziva **parsiranje** (*parsing*).

Za prepoznate rečenice i elemente u njima, prevodilac proverava ostala pravila jezika, tzv. **semantička pravila** (*semantic rules*).

Konačno, za one elemente rečenica za koje je to definisano semantikom jezika, prevodilac generiše sadržaj u prevedenom objektnom fajlu u kome se principijelno nalazi:

- binarni mašinski kod za mašinske (procesorske) instrukcije naredbi tela funkcije (potprograma)

- alociran prostor za statičke objekte (podatke), tj. sa tzv. statičkim trajanjem skladištenja

Prevodilac u **tabeli simbola** čuva informacije o svakom deklarisanom identifikatoru. 

Prevodilac u prevedenom fajlu ostavlja i informacije o svim imenima (simbolima) koja su definisana u datom fajlu, a mogu se koristiti u drugim fajlovima - **imena sa spoljašnjim vezivanjem** (*external linking*).

Imena koja imaju **interno vezivanje** (*internal linking*) ne mogu se koristiti u drugim fajlovima.

Da bismo napravili deklaraciju koja nije i definicija, za takav statički objekat potrebno je navesti ključnu reč `extern`. Sada prevodilac neće alocirati prostor za ovaj objekat (`extern int n = 0;`).

Zadatak da od skupa objektnih fajlova napravi program (tj.izvršiv fajl) ima program koji se naziva **povezivač (*linker*)**. Linkeru se zadaje spisak ulaznih objektnih (.obj) fajlova i zadatak je da je napravi **izvršni (*executable*, .exe**) fajl kao svoj izlaz.

Linker taj zadatak obavlja u dva prolaza:

- u prvom prolazu analizira ulazne fajlove, veličinu sadržaja (prevoda) i pravi mapu exe fajla, sakuplja informacije iz tabele simbola obj fajlova i izgrađuje svoju tabelu simbola

- u drugom prolazu generiše binarni kod i ujedno razrešava nerazrešena adresna polja mašinskih instrukcija na osnovu informacija o adresama u koje se preslikavaju simboli iz njegove tabele simbola

**Biblioteka (library)** je fajl sa tipičnom ekstenzijom (.lib), koja ima principijelno isti format kao i objektni fajl. Razlika je u tome što je obj fajl nastao prevođenjem jednog izvornog fajla, dok je lib nastao povezivanjem više obj (i moguće drugih lib) fajlova u jedan lib fajl.

Linker može da prijavi samo dve vrste grešaka:

- simbol nije definisan

- simbol je višestruko definisan


### Organizacija i alokacija memorije

U monoprocesnom sistemu, u memoriji je samo jedan proces, pa može da koristi sav memorijski prostor koji mu je na raspolaganju. Unutar svog raspoloživog prostora, proces može da organizuje logičke segmente (programski kod, statički podaci, prostor za alokaciju dinamičkih podataka, stek) na proizvoljan način.

U multiprocesnom sistemu treba smestiti više procesa u deo RAM-a raspoloživ za procese. Najjednostavniji način je da se raspoloživi prostor podeli na N jednakih i disjunktnih delova, particija - **particionisanje**. OS vodi jednostavnu evidenciju o tome koja je particija slobodna, a koja zauzeta, kao i evidenciju o tome u kojoj particiji se proces izvršava.

Sada adresa od koje počinje prostor dodeljen procesu nije više poznata unapred, tj. za vreme prevođenja/pisanja asemblerskog koda, pa adresa kojom se adresira fizička memorija (**fizička adresa**) nije ista kao ona koju je generisala instrukcija (**logička adresa**). Fizička adresa se dobija sabiranjem logičke adrese i **bazne adrese** procesa, adrese početka oblasti u memoriji koju zauzima proces.

Skup adresa koje instrukcije mogu da generišu čini **logički (virtuelni)** adresni prostor svakog procesa (uglavnom počinje od 0). Preslikavanje logičke (virtuelne) adrese u fizičku vrši se pri svakom adresiranju memorije tokom izvršavanja instrukcije, i za adresiranje instrukcija i podataka, potencijalno više puta tokom iste instrukcije. Zato se time bavi poseban deo procesora MMU (*memory management unit*).

Proces je **relokatibilan**, tj. može se premestiti u drugu particiju prostim kopiranjem.

Deo memorije koji je neiskorišćen (slobodan), ali se ne može iskoristiti ni za šta drugo, jer je unutar prostora alociranog i rezervisanog samo za onog ko ga koristi, naziva se **interni fragment** (*internal fragment*), a ova pojava **interna fragmentacija**.

Delimično rešenje problema particionisanja je **kontinualna alokacija**. Proces zauzima samo onoliko memorije koliko mu je potrebno, tu informaciju OS ima u exe fajlu programa - "memorijski otisak" (*footprint*) binarnog sadržaja.

Preslikavanje logičke (virtuelne) adrese i fizičku izgleda isto kao i za particionisanje. Pre samog preslikavanja MMU mora da proveri da li je generisanja logička adresa veća od stvarne veličine prostora dodeljenog procesu. Informacija o stvarnoj veličini prostora tekućeg procesa je dostupa u **registru granice** ili registru veličine. Ukoliko MMU detektuje prekoračenje procesor će generisati **izuzetak** (*exception*), signal da je instrukcija napravila prestup u pristupu memoriji (***memory access violation***).

Kada se proces ugasi prostor koji je zauzimao se oslobađa, u listu se dodaje oslobođeni fragment, uz spajanje sa eventualno postojećim slobodnim fragmentom ispred ili iza onog koji je zauzimao proces, kako bi se ukrupnili slobodni fragmenti. Slobodni fragmenti su sada **eksterni**, jer se nalaze izvan prostora koji je nekome dodeljen - **eksterna fragmentacija**.

Kada treba da pronađe mesto za smeštanje procesa, OS treba da pronađe slobodan fragment dovoljne veličine - **algoritmom dinamičke alokacije**:

- prvi koji odgovara (*firs fit*) - najjednostavniji algoritam

- onaj koji najbolje odgovara (*best fit*) - smanjenje eksterne fragmentacije

- onaj koji najlošije odgovara (*worst fit*) - u cilju da preostali slobodan fragment bude što upotrebljiviji

Nakon dužeg rada sistema, slobodna memorija može da postane jako fragmentirana, tako da se ni jedan fragment ne može da se iskoristi za novu alokaciju, i ako je ukupna količina memorije sasvim dovoljna. Moguće rešenje je **kompakcija** slobodnog prostora, kernel relocira sve procese tako da ih slaže jedan iza drugog, tako da sav slobodan prostor fuzioniše u samo jedan slobodan fragment na samom kraju.

**Segmentna organizacija** - logički adresni prostor procesa se podeli na segmente, tako da prvih nekoliko bita logičke (virtuelne) adrese određuje broj segmenata u adresnom prostoru. Sadržaj procesa se podeli na logičke celine prema sadržaju (segment za kod, za podatke, za stek...). Svaki segment se može smestiti u fizičku memoriju na proizvoljno mesto, svaki segment ima svoju baznu adresu.

OS za svaki proces organizuje posebnu strukturu podataka, **tabelu preslikavanja segmenata** (*segment map table*, SMT) koju koristi MMU pri svakom preslikavanju. SMT sadrži po jedan ulaz - **deskriptor** za svaki segment u virtuelnom adresnom prostoru. Deskriptor je određene veličine koja je potrebna da se smeste navedene informacije (bazna adresa i veličina segmenta), određen broj adresibilnih jedinica (mali stepen dvojke, npr. 4, 8, 16). SMT se nalazi u memorijskom prostoru kernela.

Da bi MMU znao gde da pronađe tabelu za tekući proces, mora posedovati tu adresu u specijalizovanom, programski dostupnom registru **SMTP (*segment map table pointer*)**. Na osnovu vrednosti u SMTP, broja segmenta i veličine segmenta i veličine deskriptora, MMU izračunava (fizičku) adresu deskriptora:

    descr_addr = SMTP + segment_no * descr_size

Ako se u deskriptoru pronađe specijalna vrednost *null* koji znači da adresirani segment nije u upotrebi izvršavanje instrukcija se prekida i signalizira se prestup u adresiranju memorije. U suprotnom MMU proverava pomeraj iz virtuelne adrese u odnosu na granicu dobijenu iz deskriptora. Ukoliko pomeraj prekoračuje granicu stvarne veličine segmenta, izvršavanje instrukcije se prekida i signalizira se prekoračenje granice segmenta. 

Ukoliko ove provere prođu bez izuzetaka, fizička adresa se dobija kao zbir bazne adrese dobijene iz deskriptora i pomeraja iz virtuelne adrese:

    p_addr = base_addr + offset

U asembleru se segmenti mogu definisati posebnim direktivama, a asembler to onda prevodi u odgovarajući format zapisa u obj/exe fajlu. Direktiva `seg` kojom započinje definicija segmenta, a koja se završava direktivom `end`. Direktivom `org` na početku zadaje se početna adresa segmenta.

OS može pružiti uslugu **dinamičke alokacije** logičkog segmenta (regiona) u virtuelnom adresnom prostoru, koju onda proces može tražiti sistemskim pozivu, tokom svog izvršavanja. Efekat ove operacije isti su kao i kada se logički segment kreira statički na osnovu definicije u exe fajlu.

Rešenje problema kontinualne alokacije - **segmentno-stranična organizacija**:

- logički (virtuelni) prostor procesa se podeli na segmente iste maksimalne veličine (uvek stepen dvojke)

- svaki segment se logički deli na **stranice (*page*)** iste veličine (uvek stepen dvojke)

- segment može imati različitu stvarnu veličinu, ali uvek zaokruženu na cele stranice

- fizička memorija logički je podeljena **okvire (*frame*)** veličine jednake veličini stranice

- jedinica alokacije je sada jedna stranica: svaka stranica može se alocirati u bilo koji okvir i uvek se alocira ceo okvir za smeštanje stranice

Virtuelna adresa sada ima 3 polja: broj segmenta, broj stranice unutar segmenta i pomeraj unutar strance. Registar SMTP procesora ukazuje na SMT tekućeg procesa. SMT svakog procesa sadrži po jedan ulaz - deskriptor za svaki segment u virtuelnom prostoru, ali taj deskriptor ne sadrži baznu adresu, već samo granicu (*limit*), i to izraženu u broju korišćenih stranica tog segmenta.

Za svaki segment svakog procesa postoji **tabela preslikavanja stranica** (*page map table*, PMT). Deskriptor alociranog segmenta u SMT ukazuje na početak PMT za taj segment tog procesa. PMT ima po jedan ulaz za svaku stranicu unutar jednog segmenta, taj ulaz sadrži broj okvira fizičke memorije u koji je stranica smeštena (*null* ako ta stranica nije alocirana).

MMU izračunava adresu deskriptora segmenta na osnovu broja segmenta u virtuelnoj adresi i vrednosti registra u SMTP, a zatim dovlači deskriptor sa te adrese iz memorije i proverava da li je broj stranice iz virtuelne adrese prekoračio granicu segmenta (izuzetak se obrađuje kao i ranije). Iz deskriptora segmenta se dobija adresa početka PMT-a. Na osnovu broja stranice i te adrese, kao i veličine deskriptora stranice izračunava se adresa deskriptora stranice i on se dohvata iz memorije. Ako je deskriptor stanice *null* procesor signalizira poseban izuzetak, **straničnu grešku** (page fault).

Iz deskriptora stranice uzima se broj okvira u koji je stranica smeštena. Pošto je stranica iste veličine kao i okvir, pa je pomeraj stanice isti kao i pomeraj u odnosu na početak okvira, pomeraj iz virtuelne adrese se nadovezuje s desne strane na dobijeni broj okvira, da bi se konačno dobila fizička adresa. 

Svi okviri ravnopravni u fizičkoj memoriji tako da se bilo koja stranica može se smestiti u bilo koji okvir. Nema eksterne fragmentacije, jer se alociraju blokovi iste veličine. Dok postoji interna fragmentacija, jer unutar stranice može postojati neiskorišćen deo.

**Stranična organizacija** - Hardverska podrška za (fizičke) segmente zapravo uopšte nije neophodna. Za pojam logičkog segmenta i segmentnu organizaciju virtuelnog adresnog prostora mogu da znaju samo prevodilac/asembler i OS.

Logički (virtuelni) adresni prostor procesa se podeli na **stranice** (*page*) iste veličine (uvek stepen dvojke). Fizička memorija je logički podeljena na **okvire** (*frame*) veličine jednake veličini stranice. 

Virtuelna adresa ima dva polja: broj stranice i pomeraj (*offset*) unutar stranice. Za svaki proces OS organizuje samo **tabelu preslikavanja stranica** (*page map table*, **PMT**). Registar **PMTP** (*PMT pointer*) procesora ukazuje na PMT tekućeg procesa. PMT ima po jedan ulaz za svaku stranicu celog virtuelnog adresnog prostora (**deskriptor stranice**). 

MMU izračunava adresu deskriptora stanice na osnovu broja stranice i vrednosti registra PMTP i dovlači deskriptor stranice sa te adrese operativne memorije. Ako je u deskriptoru stranice null, procesor signalizira poseban izuzetak, tzv. **straničnu grešku** (*page fault*). Iz deskriptora stranice uzima se broj okvira u koji je stranica smeštena. Pošto je stranica iste veličine kao okvir, pa je i pomeraj unutar stranice isti kao pomeraj u odnosu na početak okvira, pomeraj se samo konkatenira s desne strane na broj okvira da bi dobila fizička adresa.

**Heš tabela** je struktura koja rešava problem preslikavanja ključeva u vrednosti (broja stranice u broj okvira), u kom je domen ključeva ogroman (ukupan skup stranica u celom virtuelnom adresnom prostoru), ali je podskup ključeva koji se pojavljuju u stvarnom preslikavanju relativno mali u odnosu na ceo domen (skup alociranih stranica).

Ideja za rešenje je da se sama PMT logički podeli u više nivoa, tako da PMT jednog nivoa predstavlja indeks tabela narednog nivoa. Za oblast koje proces uopšte nije alocirao, a koje pokriva jedan ceo ulaz u PMT jednog nivoa, PMT narednog nivoa za taj ulaz uopšte ne treba alocirati, taj ulaz ima vrednost *null*. Polje sa brojem stranice u virtuelnoj adresi je sada podeljeno na više polja koja obezbeđuju ulaz u PMT svakog nivoa. 

Problem: jedan efektivni pristup virtuelnoj memoriji vrši dva ili više pristupa fizičkoj memoriji, što višestruko usporava rad procesora sa memorijom. Rešenje: U procesoru (kao deo MMU) se organizuje memorija koja je relativno mala po kapacitetu (mnogo manja od operativne memorije), ali brza po vremenu pristupa, koja služi kao keš za deskriptore - tzv. ***Translation Lookaside Buffer* (TLB)**. TLB sadrži podskup deskriptora koji su nedavno korišćeni. MMU kada treba da preslika virtuelnu adresu najpre je traži u TLB.

TLB ni na koji način ne menja semantiku preslikavanja, već ga samo ubrzava, pa bi zato u principu bio potpuno transparentan za softver (i jeste za procese), osim jednog detalja. Ceo sadržaj TLB-a ima samo opseg važenja tekućeg procesa, pa se mora proglasiti nevalidnim prilikom promene konteksta. Ovo mora da uradi OS kada vrši promenu konteksta instrukcijom koju procesor mora da obezbedi u tu svrhu. Druga mogućnost jeste da TLB sadrži deskriptore različitih procesa, uz koje pamti i informaciju tome kom preslikavanju pripada svaki deskriptor.

**Zaštita** - postoji potreba da se proces zaštiti od samog sebe tj. od sopstvenih instrukcija, odnosno od sopstvenih grešaka zbog korupcije:

- da ne pristupa nealociranim delovima virtuelnog adresnog prostora

- da ne menja sopstvene instrukcije ili podatke koji su namenjeni samo za čitanje

- da stek ne prekorači svoju granicu i ne pregazi ostale podatke i instrukcije


U deskriptoru fizičkog segmenta/stranice nalazi se **informacija o pravima pristupa** do datog fizičkog segmenta/stranice: 

- X (*execute*) - dozvoljeno je izvršavanje sadržaja, tj. pristup u ciklusima čitanja, ali samo tokom faze dohvatanja instrukcije u procesoru (važi samo za programski kod, odnosno logičke segmente sa instrukcijama)

- R (*read*) - dozvoljeno je čitanje sadržaja, tj. pristup u ciklusima čitanja, ali samo tokom faze izvršavanja instrukcije u procesoru (važi za podatke)

- W (*write*) - dozvoljen je upis sadržaja, tj. pristup u ciklusima upisa, ali samo tokom faze izvršavanja instrukcije u procesoru (važi za podatke)


Procesor mora da podrži (najmanje) dva režima rada:

- **privilegovani** (*privileged*) ili sistemski, kernel režim - kada je u ovom režimu, procesor dozvoljava sve instrukcije i pristup do svih programskih dostupnih registara; kernel kod se izvršava u ovom režimu

- **neprivilegovani** (*non-privileged*) ili korisnički režim - u ovom režimu neki programski dostupni registri nisu dostupni instrukcijama, tj. instrukcije ne smeju da im pristupe, kao da ti registri ne postoje; u ovom režimu izvršava se kod korisničkih procesa

Procesor prelazi iz neprivilegovanog u privilegovani režim pri sistemskom pozivu, kada korisnički proces traži neku uslugu kernela ili kada instrukcija koju procesor izvršava generiše bilo koji izuzetak. Procesor tada treba da pređe na izvršavanje instrukcija koda kernela koje izvršavaju zahtev zatražen tim sistemskim pozivom ili obrađuju taj izuzetak.

Instrukcija skoka kojom se izvršava sistemski poziv mora da izvrši implicitni skok, memorijskim indirektnim adresiranjem, preko adrese koja je sadržana negde u memoriji, zapravo preko pokazivača na kod potprograma na koji se skače, a ne direktnim adresiranjem odredišta skoka. Negde u memoriji kernel organizuje posebnu strukturu, **vektor tabelu** (*vector table*, **VT**), koja ima po jednu adresu (vektor, pokazivač na lokaciju) koda kernela koji obavlja određenu operaciju. Za svaki tip izuzetka koji može generisati hardver procesora pridružuje (predefinisano, nepromenljivo) po jedan broj ulaza u vektor tabeli. Instrukcija sistemskog poziva kao svoj operand takođe ima broj ulaza u VT.

Da bi mogao da pronađe adresu koda koji obrađuje izuzetak ili sistemski poziv, procesor mora imati informaciju o adresi početka VT u memoriji - **pokazivač na tabelu vektora** (*vector table pointer*, **VTP**). Vektor tabelu kernel formira u posebnom delu operativne memorije koji je samo pod njegovom kontrolom i samo njemu dostupan, a nedostupan korisničkim procesima (potrebna zaštita prostora kernela od korisničkih procesa).

Kernel mapira svoj deo memorije u virtuelni adresni prostor svakog procesa, na isto mesto, ali označava taj prostor kao nedozvoljene za bilo kakav pristup u neprivilegovanom režimu rada procesora,

Prenos parametara u sistemski poziv:

- kroz registre opšte namene, svaki sistemski poziv očekuje određene parametre u određenim registrima

- preko steka korisničkog procesa, odakle ih kernel može pročitati

- u nekoj strukturi u memoriji, u kojoj kernel očekuje parametre složene po određenom formatu

### Deljenje memorije

Tehnika **dinamičkog učitavanja** podrazumeva da proces alociran iz fajla učitava ovakve delove samo ako su stvarno potrebni, i onda kada su potrebni, odnosno kada se takva situacija zaista i dogodi. Obaveza OS-a je samo da  obezbedi uslugu (sistemski poziv) koji alocira deo (virtuelnog) adresnog prostora, kao i uslugu kojom u dati prostor procesa učitava sadržaj nekog binarnog fajla.

Tehnika **preklopa** (*overlays*) podrazumeva da se moduli u kojima su grupisani potprogrami i/ili podaci koji se koriste zajedno, a u alternaciji sa drugim takvim modulima, dinamički učitavaju u memoriju (i izbacuju iz nje) na isto mesto, preklapajući se, pošto nikada nisu potrebni istovremeno. 

Ako neki modul koji se preklapa sadrži podatke koji se menjaju, pre nego što se na njegovo mesto potprogram učita neki drugi modul, mora da sačuva sadržaj izbačenog modula njegovim upisom u neki fajl, ako će taj modul biti ponovo kasnije potreban.

Obaveza OS-a je i dalje samo to da obezbedi uslugu (sistemski poziv) koji alocira deo (virtuelnog) adresnog prostora procesa, kao i uslugu kojom dati prostor procesa učitava sadržaj nekog binarnog fajla i sadržaj iz memorije upisuje u neki fajl.

**Logičko deljenje memorije** - u multiprocesnim sistemima je česta situacija da se kreira više procesa nad istim programom, kako se kod ne menja, a isti je u svim procesima, svi ti procesi onda mogu da dele jednu jedinu kopiju programskog koda u fizičkoj memoriji. Ako je PMT u više nivoa, a neka tabela sadrži samo stranice logičkih segmenata sa kodom, onda ovi procesi mogu koristiti istu kopiju te tabele. 

Isto važi i za podatke ukoliko procesi ne menjaju te podatke. Ukoliko neki od procesa želi da promeni neke podatke, tada se pravi stvarna fizička kopija. Ova tehnika se naziva **kopiranje pri upisu** (*copy on write*).

Postoji ponekad potreba da bilo koji procesi, čak i oni koji ne izvršavaju isti program, dele određeni segment memorije povodom razmene informacija.

**Deljenje biblioteke** - u multiprocesnim sistemima je vrlo čest slučaj da više procesa koriste iste biblioteke. Ne deli se kod celog programa, nego samo deo (kod jedne biblioteke). Taj kod treba povezati dinamički sa ostatkom programa koji koristi usluge te biblioteke. Zato se ovakve biblioteke nazivaju **(deljene) biblioteke sa dinamičkim vezivanjem** (*/shared/ dynamic linking libraries*, **DLL**).

**Zamena procesa** je tehnika gde se jedan proces izbacuje (*swap out*) iz memorije, a drugi učitava, ubacuje (*swap in*) u memoriju. Savremeni OS rade zamenu celih procesa (*swapping*) samo u izuzetnim situacijama kada je opterećene sistema veliko.

**Učitavanje stranice na zahtev** (*demand paging*) - ako neki deo virtuelnog adresnog prostora proces uopšte ne koristi tokom svog izvršavanja, te stranice neće nikada biti učitane. Za razliku od dinamičkog učitavanja, ovaj mehanizam je potpuno transparentan za proces i semantiku njegovog izvršavanja, jer ceo posao obavlja OS uz podršku hardvera.

**Zamena stranica** - U slučaju da u memoriji nema ni jednog slobodnog okvira tražena stranica će da "preotme" okvir neke druge stranice. Na taj način stranice vremenski dele fizičku memoriju. 

Procesori često imaju sledeću hardversku podršku: u deskriptoru stranice u PMT koriste jedan bit, tzv. **bit zaprljanosti** ili bit modifikacije (*dirty bit*, *modify bit*) koji MMU postavlja na 1 svaki put kada se izvrši operacija upisa u neku reč te stranice. Prilikom izbacivanja stranice, ukoliko je taj bit 0, sadržaj stranice nije potrebno snimati.

Prostor na disku u koji OS snima izbačene stranice i sa kog ih ponovo učitava naziva se **prostor za zamenu** (*swap space*). Taj prostor se može organizovati unutar nekog **fajla** koji se konfiguracijom OS-a odredi za tu namenu ili na posebnoj particiji na disku koja služi samo za tu namenu i na kojoj nije instaliran fajl sistem, na tzv. **presnoj particiji** (*raw partition*).

**Algoritam zamene stranica** (*page replacement algorithm*), tj. algoritam koji bira stranicu žrtvu" za izbacivanje, je vrlo značajan za efikasnost sistema. Sistemi najčešće primenjuju neku varijantu aproksimacije LRU algoritma (*least recently used*). Za potrebe ovog algoritma hardver procesora treba da podrži još jedan bit u deskriptoru stranice, tzv. **bit referenciranja** (*reference bit*) koji MMU postavlja prilikom svake operacije sa stranicom (i čitanja i upisa).

Sistem može da uđe u režim u kom se stranične greške dešavaju izuzetno često, iskorišćenje procesora je jako nisko, dok ulazno-izlazni podsistem za operacije sa diskom postaje preopterećen. Ovakva loša situacija naziva se **batrganje (*thrashing*)** i dobar OS mora da se štiti od nje

## Upravljanje procesima

### Procesi i niti

**Proces** je jedno izvršavanje nekog programa sa jednim (virtuelnim) adresnim prostorom. Ti procesi se izvršavaju uporedo (konkurentno) na jednom procesoru ili na više procesora (multiprocesiranjem). Procesi pokrenuti na sistemu mogu biti **interaktivni** ili **pozadinski**.

**Tok kontrole** (*control flow* ili *flow of control*) - redosled sekvencijalnog izvršavanja instrukcija, jedne po jedne, u kom iza prethodne sledi sledeća koja je odmah iza nje u memoriji osim ako instrukcija ne uradi drugačije. 

**Stanje** (*state*) registara procesora i lokacija memorije, adresiranih adresama koje generiše instrukcija raspoloživim načinima adresiranja, pri čemu stanje koje za sobom ostavi prethodno izvršena instrukcija u toku kontrole, sledeća instrukcija u tom toku zatiče u registrima ili lokacijama memorije.

**Promena konteksta** je postupak koji obavlja OS i koji ovo obezbeđuje. Pre nego što procesor pređe na izvršavanje instrukcija drugog procesa OS sačuva stanje registara procesa čije izvršavanje se prekida, a potom restaurira stanje registara procesa na čije izvršavanje prelazi.

Jedan proces može kreirati nov proces sistemskim pozivom, proces roditelj kreira proces dete. Proces može kreirati proizvoljno mnogo novih procesa sistemskim pozivima. Sistemski poziv može biti takav da se proces kreira nad zadatim programom, uz opcioni prenos argumenata. U takvim sistemskim pozivima nov proces dete izvršava zadati program sa svojim novim adresnim prostorom, inicijalizovanim prema sadržaju exe fajla. 

Na sistemima nalik Unix proces roditelj kreira nov proces dete sistemskim pozivom `fork` (račva). Ovaj sistemski poziv kreira identičnu kopiju ("klon") procesa roditelja. Ukoliko ovaj sistemski poziv uspe postoje dva toka kontrole koja nastavljaju svoja izvršavanja povratkom iz funkcije `fork`. Celobrojna vrednost identifikatora procesa je jedinstvena identifikacija koja se kasnije upotrebljava kao argument sistemskih poziva za operacije nad procesom koji se sa tim identifikatorom identifikuje. `Fork` vraća 0 u kontekstu (toku kontrole) procesa deteta, a vrednost veću od 0 u kontekstu roditelja (*process id*, pid). 

Pored sistemskog poziva fork, sistemi nalik sistemu Unix poseduju sistemski poziv `exec`, tj. čitavu familiju sličnih funkcija sa istim efektom, uz varijaciju parametara. Ne kreira se nikakav nov proces, kao entitet u OS-u, već se ceo postojeći memorijski kontekst tekućeg procesa (onog koji je pozvao `exec`) potpuno odbacuje i iznova inicijalizuje iz zapisa u exe fajlu koji je zadat parametrom ovog poziva i započne tok kontrole ispočetka, izvršavanjem programa u tom exe fajlu.

Proces može ugasiti sebe eksplicitnim zahtevom, odnosno tražiti završetak (termination) svog izvršavanja sistemskim pozivom `exit`. Ovaj sistemski poziv prima jedan parametar koji ima značenje "informacije o statusu" koji OS prenosi roditeljskom procesu procesa koji se gasi. Prema konvenciji vrednost 0 označava "regularan završetak". Interpretacija ove vrednosti je u svakom slučaju na roditeljskom procesu, a on taj status može dobiti preko sistemskog poziva `wait`. Parametar status ovog poziva se prenosi pokazivač na celobrojnu promenljivu u koju će ovaj sistemski poziv upisati status procesa deteta po njegovom gašenju.

Operativni sistemi po pravilu omogućavaju i to da jedan proces ugasi neki drugi proces sistemskim pozivu. Ovaj sistemski poziv se tradicionalno naziva `kill`. Ovaj sistemski poziv na sistemima nalik sistemu Unix ne predstavlja eksplicitnu operaciju gašenja procesa, već zahtev za slanjem signala navedenom odredišnom procesu. **Signal** je prosta informacija o identifikaciji nekakve proste poruke, tipično jednostavna celobrojna vrednost.

**Nit (thread)** predstavlja tok kontrole koji teče uporedo sa drugim tokovima kontrole, ali koji deli virtuelni adresni prostor sa nekim drugim tokom ili tokovima kontrole (nitima). Svaka nit ima svoj kontekst izvršavanja, svoje stanje registara procesora (uključujući PC i SP) i svoj stek. Sa druge strane, nekoliko niti može da deli zajednički ostatak adresnog prostora (osim steka), kao i resurse operativnog sistema (otvoreni fajlovi, standardni ulazni i izlazni uređaji, ...).

Motiv za korišćenje nit je uporedo obavljanje nekih aktivnosti ili obrada, ili reakcije na događaje iz okruženja koji se dešavaju asinhrono. Svakoj aktivnosti ili obradi događaja posvećuje se poseban tok kontrole koji predstavlja sekvencijalno izvršavanje, a koji se bavi samo tom aktivnošću ili obradom događaja. OS vodi računa o tome da uporedne tokove kontrole rasporedi na više procesora, ako postoje, kako bi se izvršavale paralelno. Ovakvi tokovi kontrole obrađuju neke deljene strukture podataka, razmenjuju informacije preko tih podataka i izvršavaju iste potprograme. 

### Implementacija procesa niti

**Preotimanje** (*preemption*) je situacija u kojoj procesor izvršava instrukcije jednog procesa, dogodi se nešto zbog čega neki drugi proces može da nastavi izvršavanje i on treba da preuzme procesor što pre, jer je njegova reakcija važnija od onoga što radi tekući proces, ne čekajući da se proces odrekne procesora sistemskim pozivom. Da bi se izvršila promena konteksta, neophodno je da procesor pređe na instrukcije koje pripadaju kodu kernela i koje izvršavaju promenu konteksta.

Događaj za promenu konteksta može biti signaliziran posebnim hardverskim signalom koji predstavlja spoljašnji **zahtev za prekid** (*interrupt request*). Kada stigne zahtev za prekid, procesor završava tekuću instrukciju, i u principu radi isto što i kod obrade izuzetka: čuva kontekst (neke od programski dostupnih registara) na steku i prelazi na izvršavanje posebnog programa za obradu prekida - **prekidne rutine** (*interrupt routine*). Procesori po pravilu omogućuju da se programskim putem, odgovarajućim instrukcijama, zabrane spoljašnji prekidi - tzv. **maskiranje prekida** (*interrupt masking*). Prekid se prihvata samo ako nije selektivno ili globalno maskiran, ako jeste prekid se prosto ignoriše.

Informacije koje OS vodi o svakom procesu nazivaju se i **kontekstom procesa** (process context) i sadrže svojstva (atribute) svakog procesa:

- identifikator procesa (*process ID*, pid)

- kontekst procesora ili kontekst izvršavanja

- informacije potrebne za raspoređivanje procesa na procesoru (*scheduling context*)

- memorijski kontekst za virtuelni adresni prostor procesa

- deskriptori resursa koje je proces alocirao

- "knjigovodstvo" (*accounting*) - evidencija korišćenja resursa računara i operativnog sistema

Tradicionalno, struktura podataka kojom se predstavlja proces u sistemu naziva se **kontrolni blok procesa** (*process control block*, PCB).

Konceptualno, tokom svog životnog veka, tj. za vreme od kada je traženo njegovo kreiranje, pa dok se ne ugasi, svaki proces prolazi kroz određena **stanja**:

- stanje inicijalizacije (*initializing*)

- terminalno stanje (*terminating*) - od trenutka kada je traženo gašenje procesa, dok on sasvim ne nestane iz operativnog sistema kao entitet 

- izvršava se (*running*) - trenutno se izvršava na procesoru

- spreman za izvršavanje (*ready*)

- suspendovan ili blokiran, čeka (*suspended*, *blocked*, *waiting*) - proces čeka na ispunjenje uslova nastavka svog izvršavanja

Načini na koje dolazi do promene konteksta: 

- **sinhrono** - kao posledica izvršavanja same tekuće instrukcije procesa

- **asinhrono** - potpuno nezavisno od tekuće instrukcije i onoga što ona radi, u proizvoljnim, nepredvidivim trenucima vremena, kao posledica spoljašnjeg hardverskog prekida (*interrupt*)

Kao posledica ovih situacija procesor prelazi u privilegovani režim rada i najčešće prebacuje na drugi sistemski stek na koji ukazuje sistemski SP. Procesor takođe čuva određene programski dostupne registre prepisujući ih negde (npr. stek) i u PC upisuje adresu koju je dohvatio iz vektor tabele za dati ulaz. Nakon obrade te situacije, OS mora da povrati kontekst procesa koji je odabran za izvršavanje i vrati se na njegovo izvršavanje, tako da on nastavlja od mesta na kom je prekinut.

Procesorski kontekst je moguće čuvati u strukturi unutar PCB koja je za to namenjena ili na steku procesa, a samo vrednost SP sačuvati u PCB.

Pod određenim uslovima, promena konteksta se može izvršiti i bez ijedne asemblerske instrukcije, time nezavisno od procesora, korišćenjem samo standardne biblioteke jezika C čije su deklaracije u zaglavlju `setjmp.h`:

- `type jmp_buf` - struktura koja sadrži polja za čuvanje vrednosti svih programski dostupnih registara koji dati prevodilac koristi na datom procesoru

- `int setjmp` (`jmp_buf` context) - funkcija koja čuva kontekst procesora u strukturi datu parametrom i vraća 0

- `void longjmp` (`jmp_buf context, int value`) - restaurira kontekst dat kao argument, a koji je sačuvan pomoću setjmp 

Najefikasnije je kada OS podržava koncept niti, a izvršno okruženje onda može da preslikava niti iz programa u niti operativnog sistema, i to na različite načine:

- jedan u jedan: svaka nit u programu implementira se jednom niti operativnog sistema

- više u jedan: više niti u programu implementira se jednom niti operativnog sistema, a promenu konteksta između njih obavlja izvršno okruženje

- više u više

Izbor procesa za izvršavanje i te kako može da utiče na vremensko ponašanje sistema, odnosno vreme odziva i performanse celog sistema. Zato je **algoritam raspoređivanja procesa na procesoru (*process scheduling*)** izuzetno bitan element svakog kernela.

Najjednostavniji algoritam jeste opsluživanje po redosledu dolaska (first come - first served, FCFS ili FIFO). Procesor dobija proces koji je najdavnije došao u red spremnih. Međutim ovaj algoritam ima ozbiljne nedostatke, procesi koji se veoma kratko izvršavaju mogu dugo da čekaju ukoliko su ispred njih u redu procesi koji se vrlo dugo izvršavaju.

Jedan, teorijski optimalan, ali praktično neprimenljiv u egzaktnoj formi, jeste algoritam najkraći posao prvi. U današnjim sistemima upotrebljavaju se mnogi sofisticiraniji algoritmi, od kojih značajnu grupu čine algoritmi zasnovani na prioritetima (*priority*).

U sistemima sa raspodelom vremena koristi se tzv. ***round robin*** algoritam. Kružno opsluživanje spremnih procesa, isto kao FIFO, ali sa ograničenim vremenskim odsečkom.

### Sinhronizacija procesa

U mnogim prilikama postoji potreba da procesi interaguju, na primer tako što će razmenjivati informacije. Ovakvi procesi se nazivaju **kooperativni procesi** (*cooperating processes*). Problemi koji nastaju zbog konkurentnosti (konflikti) posledica su interakcije između uporednih tokova kontrole.

Jedan veoma čest obrazac, model saradnje između uporednih procesa jeste tzv. model **proizvođač-potrošač** (*producer-consumer*). Jedan proces ili više njih proizvode nekakve informacije, podatke ili poruke koje treba da da proslede, a jedan ili više njih konzumiraju (troše) te informacije, podatke, pakete ili poruke koje je proizveo proizvođač.

Podrazumevano se procesi izvršavaju uporedo (*concurrently*), što znači da se sekvence njihovih instrukcija izvršavaju proizvoljno prepleteno ili čak fizički paralelno. **Paralelno** izvršavanje ili paralelizam podrazumeva fizički istovremeno izvršavanje, što je moguće samo na više procesora. **Konkurentnost** podrazumeva mogućnost takvog paralelnog izvršavanja, ukoliko za to postoje mogućnosti, a u svakom slučaju podrazumeva multiprogramiranje sa nepredvidivim načinom preplitanja izvršavanja instrukcija uporednih procesa. Kod kooperativnih sistema rezultat može zavisiti od načina prepletanja njihovih instrukcija, pa zato može biti nepredvidiv.

Uvođenje ograničenja u pogledu načina preplitanja akcija uporednih procesa ili načina njihovog napredovanja, koja onda izvršno okruženje ili OS moraju zadovoljiti tokom uporednog izvršavanja procesa, naziva se **sinhronizacija** (*synchronization*). 

Jedan tip sinhronizacije predstavlja **uslovna sinhronizacija**: neki proces ne sme da nastavi izvršavanje iza neke tačke, tj. ne sme da izvršava neke akcije ukoliko neki drugi proces nije uradio nešto, ili ukoliko nije ispunjen neki uslov, ili ukoliko neki proces ili podatak nije u nekom potrebnom stanju i slično.

Postoje sekvence instrukcija, odnosno sekcije koda uporednih procesa koja treba izvršavati nedeljivo, atomično ili, kako se najispravnije kaže izolovano, tako da njihov efekat bude takav kao da drugih procesa nema, odnosno kao da tokom njihovog izvršavanja nema interakcije sa drugim procesima i njihovog uticaja. Ovakve sekcije koda uporednih procesa nazivaju se **kritične sekcije** (*critical section*).

Ako jedan proces uđe u kritičnu sekciju, drugi procesi ne smeju da budu u svojim kritičnim sekcijama koje su sa tom u potencijalnom konfliktu, niti da uđu u njih. Ovakva sinhronizacija naziva se **međusobno isključenje** (*mutual exclusion*).

U najjednostavnijem slučaju međusobno isključenje unutar samog kernela se može obezbediti tako što se ceo kernel posmatra kao kritična sekcija. To znači da je pri svakom ulasku u kernel kod, na svim mestima, potrebno uraditi neki ulazni protokol, "zaključavanje" ulaska u kritičnu sekciju (`lock()`), a na svakom izlasku izlazni protokol "otključavanje" (`unlock()`).

- `lock()` - podrazumeva maskiranje spoljašnjih prekida

- `unlock()` - podrazumeva demaskiranje spoljašnjih prekida

Ovo nije dovoljno u (simetričnim) multiprocesorskim sistemima. Jedan procesor može da uđe u kritičnu sekciju (kod kernela), maskira prekide (i time se "zaštiti od samog sebe"), ali ništa ne sprečava neki drugi procesor da uradi isto i uđe u kod kernela. Za međusobno isključenje izvršavanja na više procesora potrebna je podrška hardvera. Procesori imaju tu podršku u vidu instrukcija koje mogu da imaju vrlo različit, ali i vrlo sličan oblik i semantiku. Dva osnovna tipa ovakvih instrukcija su:

- `test-and-set` - atomično čita i vraća vrednost sadržaja zadate (adresirane) memorijske lokacije, a u tu lokaciju postavlja 1
  
- `swap` - atomično zamenjuje vrednosti registra i adresirane memorijske lokacije

**Semafor** je jedan jednostavan i efikasan koncept za sinhronizaciju procesa. Semafor je objekat, promenljiva ili apstraktan tip podataka, koji ima svoje stanje, predstavljeno celobrojnom vrednošću, kao i dve operacije koje uporedni procesi mogu da vrše nad njim:

- `wait` (P) - vrednost semafora koja se dekrementira i ako je nakon toga postala manja od 0, proces koji je izvršio ovu operaciju mora da čeka na semaforu

- `signal` (V) - vrednost semafora se inkrementira, a ako je pre toga bila manja od 0, jedan proces koji je čekao na tom semaforu nastavlja svoje izvršavanje 

Mnogi sistemi podržavaju i posebne, **binarne semafore** čija je semantika u osnovi jednostavna. Imaju samo dve vrednosti, 0 i 1. `Wait`: ako je vrednost semafora 1, postavlja se na 0, a proces nastavlja, u suprotnom proces čeka. `Signal`: ako postoje procesi koji čekaju, jedan se blokira, u suprotnom vrednost se postavlja na 1.

Varijante binarnih semafora:

- `mutex` - binarni semafor namenjen samo za međusobno isključenje kritičnih sekcija, poseduje ograničenje da samo proces koji je zatvorio semafor operacijom tipa wait može da ga otvori operacijom signal
  
- `event` - služi za signalizaciju događaja koji mogu doći i od hardvera, pa se operacija signal može vezati i kao reakcija na spoljašnji prekid od hardvera 

**Mrtva** ili **kružna blokada** (*deadlock*) nastaje kada se n procesa međusobno kružno blokira, tako što proces P1 drži zaključan resurs/semafor/kritičnu/sekciju R1 a pritom čeka na resurs R2, proces P2 drži zauzet resurs R2 a čeka na resurs R3 itd, proces Pn drži resurs Rn a čeka na resurs P1. U odnosu na živu blokadu (*livelock*) razlika je u tome što se sada procesi ne izvršavaju, nego su trajno suspendovani, dok kod žive blokade neograničeno izvršavaju petlje uposlenog čekanja.

Optimistički pristup kontroli konkurentnosti ili optimističko zaključavanje podrazumeva ponašanje kao da se konflikt neće ni dogoditi, tačnije, da je mala šansa da se on dogodi. Promena podataka obavlja se bez zaključavanja i čekanja, ali pošto se konflikt ipak može dogoditi, sprovode se tehnike koje mogu da detektuju takav konflikt. U slučaju detektovanja konflikta promena se otkazuje i pokušava ponovo.

Sinhronizacija je samo jedan vid interakcije uporednih procesa, drugi vid je **međuprocesna komunikacija** (*inter-process communication*, IPC), razmena informacija između procesa. Postoje dva fundamentalna logička modela međuprocesne komunikacije:

- deljena promenljiva ili deljeni objekat ili deljeni podatak - postoji deljeni podatak ili objekat kom mogu pristupati uporedni procesi, tako da neki od njih upisuju u taj podatak, a neki od njih iz njega čitaju i na taj način razmenjuju informacije
	
- razmena poruka - jedan proces eksplicitno, npr. sistemskim pozivom ili jezičkim konstruktom, zahteva slanje poruke odredišnom procesu ili procesima, a proces primalac, ili više njih, eksplicitno traže prijem poruke

## Ulazno-izlazni podsistem

### Interfejs ulazno-izlaznog podsistema

