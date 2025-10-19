# Sistemi u realnom vremenu

**Sistemi u realnom vremenu (19E044SRV)** - Slajdovi za vežbe (2024/2025)

**as. ms Haris Turkmanović**

*Elektrotehnički fakultet u Beogradu*

## RTOS

***Task*** predstavlja nezavisnu logičku celinu u kodu enkapsuliranu u vidu programske funkcije. Sa stanovišta programskog jezika *task* je specifična funkcija koja:

- u okviru svoje definicije ima jednu beskonačnu programsku petlju 

- ne poziva se kao druge funkcije već se samo jednom kreira od strane Scheduler-a operativnog sistema 

Pseudo-kod koji opisuje definiciju jedne tipične *task* funkcije je:

```c
void Task(arguments) {
    // Task data initialization
    // go to endless loop
    while(1) {
        // Task algorithm
    }
}
```

Kada se task izvršava na nekoj platformi on koristi resurse te platforme (registre, stek, ...) kao da je jedinstveni task u sistemu. Kako bi se zapamtili resursi dodeljeni *task*-u ali i sačuvalo stanje određenih resursa (na primer stanje registara CPUa) bitnih za izvršavanje *task*-a, svakom kreiranom *task*-u se dodeljuje struktura nazvana **kontekst *task*-a**.

Svakom novokreiranom *task*-u dodeljuje se **prioritet**. U slučaju korišćenja algoritma raspoređivanja koji koriste prioritet *task*-ova, prioritet *task*-a određuje koji od dva *task*-a će dobiti procesorsko vreme ukoliko su oba *task*-a spremna za izvršavanje.

U većini realizacija RTOS-a, *task* može imati neko od sledećih stanja:

- ***Running*** – *task* se izvršava na procesoru

- ***Ready*** – *task* je spreman za izvršavanje, ali se ne izvršava (verovatno jer se trenutno izvršava task većeg ili istog prioriteta)

- ***Blocking*** – *task* je blokiran i čeka na neki događaj u sistemu

U zavisnosti od realizacija RTOS-a mogu postojati i dodatna stanja (na primer ***Suspended*** u slučaju FreeRTOS-a). U većini slučajeva uvek postoje stanja kao što su *Running*, *Ready* and *Blocking*.

U okviru kernela operativnog sistema, komponenta pod nazivom ***Scheduler*** (jezgro kernela) ima zadatak da vrši raspoređivanje *task*-ova. Raspoređivanje *task*-ova zapravo podrazumeva odlučivanje o tome kom će *task*-u u posmatranom trenutku biti dodeljeno procesorsko vreme. Postoji mnoštvo različitih algoritama za raspoređivanje *task*-ova koji prilikom raspoređivanja razmatraju različite parametre *task*-a ili sistema. Dva najčešća algoritma raspoređivanja su:

- **Round-Robin algoritam** - svaki *task* dobija isto vreme za izvršavanje

- **Priority Round-Robin algoritam** - *task* najvećeg prioriteta dobija procesorsko vreme

Tri najčešća mesta u toku izvršavanja programa gde se poziva *Scheduler* su:

1. Kada trenutni *task* koji se izvršava odlazi u blokirano stanje, a nije došlo do isteka sistemskog tajmera.

2. Kada usled generisanja prekida *task* većeg prioriteta prelazi iz stanja "Blokiran" u stanje "Spreman za izvršavanje"

3. Usled isteka sistemskog tajmera

Ukoliko dolazi do dodele procesorskog vremena nekom *task*-u koji nije trenutni *task* koji se izvršava na procesoru, onda se vrši **proces zamene konteksta**. Kada *task* dobije procesorsko vreme kontekst procesora na kome se *task* izvršava (sadržaj steka stek, vrednosti registara CPUa) mora biti isti kao kontekst procesora neposredno pre odlaska *task*-a u stanje "Blokiran" ili stanje "Spreman za izvršavanje"

Proces zamene konteksta se sastoji se od dve faze:

1. Čuvanje konteksta procesora trenutnog *task*-a

2. Restauracija konteksta procesora *task*-a koji je dobi procesorsko vreme

## FreeRTOS 

**FreeRTOS** je *Open Source* RTOS kernel pogodan za implementaciju *Real-Time embedded* aplikacija.

Konfigurisanje FreeRTOS-a se vrši u okviru FreeRTOSConfig.h header fajla. U okviru ovog fajla moguće je izvršiti podešavanje konfigurabilnih parametara FreeRTOS-a. Fajl uglavnom  čine makroi. Promenom vrednosti makroa u header fajlu moguće je uključiti/isključiti određene funkcionalnosti FreeRTOS-a.

Algoritmi raspoređivanja *task*-ova:

- **Kooperativno raspoređivanje** - svi *task*-ovi su istog prioriteta, promena konteksta se vrši samo kada *task*-ovi prepuste kontrolu

- **Round-Robin raspoređivanje** - svi *task*-ovi su istog prioriteta, *Scheduler* brine o tome da svaki *task* dobije isto vreme za izvršavanje

- ***Preemption* raspoređivanje** - raspoređivanje sa kontrolom pristupa, *Scheduler* aktivira *task* najvišeg prioriteta

```c
#define configUSE_PREEMPTION 1          // Preemption algoritam raspoređivanja
#define configUSE_TIME_SLICING 1        // Za taskove istog prioriteta primenjuje Round-Robin
```

U većini *embedded* aplikacija, baziranih na RTOS-u, neophodno je obezbediti periodično pozivanje algoritama za raspoređivanje *task*-ova. Ova funkcionalnost se u okviru *embedded* platforme realizuje koristeći neki od dostupnih tajmera te *embedded* platforme.

```c
#define configTICK_VECTOR TIMER_A0_VECTOR
```

U okviru prekidne rutine tajmera poziva se *Scheduler*. Moguće je konfigurisati FreeRTOS *Scheduler* tako da se u okviru prekidne rutine sistemskog tajmera poziva proizvoljna *callback* funkcija definisana u okviru aplikacija.

```c
#define configUSE_TICK_HOOK 1
```

Na svaki istek sistemskog tajmera poziva se korisnički definisana funkcija koja mora imati sledeći potpis:

```c
void vApplicationTickHook(void);
```

Funkcija se izvršava u okviru prekidne rutine, tako da je poželjno da bude kratka, ne koristi puno steka i da ne zove API funkcije koje se ne završavaju sa `FromISR`.

Većina aplikacija baziranih na RTOS imaju sledeći tok izvršavanja u okviru `main` funkcije:

1. Inicijalizacija hardvera

2.  Kreiranje objekata RTOS-a

3.  Startovanje *Scheduler*-a

Ukoliko je sistem dobro inicijalizovan i ukoliko su objekti uspešno kreirani, poziv *Scheduler*-a sa programerskog stanovišta predstavlja funkciju iz koje se nikada ne vraćamo. U okviru FreeRTOS-a se poziv *Scheduler*-a realizuje pozivom funkcije:

```c
vTaskStartScheduler();      // Start the Scheduler
```

## *Task*-ovi

Svakom kreiranom *task*-u je moguće dodeliti prioritet. Opseg prioriteta *task*-ova se kreće od `0` do `(configMAX_PRIORITIES – 1)`. Makro `configMAX_PRIORITIES` je moguće menjati u okviru konfiguracije FreeRTOS-a

Funkcionalnosti FreeRTOS *task*-a su implementirane u okviru klasične C-ovske funkcije tzv. "*Task* funkcija". *Task* funkcija mora imati sledeći potpis (deklaraciju):

```c
void vTaskFunctionName(void* pvParameter);
```

Osobine *Task* funkcije:

- U funkciju se ulazi samo jednom, funkciju poziva scheduler nakon startovanja

- Funkcionalnost *task*-a se implementira u okviru beskonačne petlje

- Iz *Task* funkcije se ne izlazi eksplicitno (klasičnim pozivom `return` naredbe) - Ukoliko je potrebno izaći iz funkcije (*task* više nije potreban) potrebno ga je izbrisati.

- Jedna *Task* funkcija se može koristi kao izvršna funkcija više *task*-ova. U tom slučaju svaki kreirani *task* će imati svoju posebnu instancu *Task* funkcije koja će imati svoj zaseban stek.

Struktura koda jedne tipične *task* funkcije u FreeRTOS-u:

```c
void ATaskFunction(void* pvParameters) {
    // Variable declarations
    int32_t varExample = 0;
    
    // Infinite loop
    for(;;) {
        // Code
    }

    // The task must be deleted before reaching the end of its implementation
    vTaskDelete(NULL);
}
```

Task može biti u jednom od sledećih stanja:

- ***Running*** - *task* se trenutno izvršava
    - Na platformi koja ima jedno procesorsko jezgro samo jedan *task* u sistemu može biti u ovom stanju
- ***Ready*** – *task* je u listi *task*-ova spremnih za izvršavanje
    - *Task* nije u stanju *Blocked* ili *Suspended* ali se trenutno ne izvršava jer postoji drugi *task* jednakog ili višeg prioriteta koji se trenutno nalazi u stanju *Running*
- **Blocked** - *task* je blokiran i čeka generisanje nekog događaja
    - *Task* se može blokirati čekajući na semaforu, grupi događaja, queue ili notifikaciji

- **Suspended** - *task* koji se nalazi u ovom stanju ne učestvuje u raspoređivanju od strane *Scheduler*-a
    - *Task* ulazi u ovo stanje isključivo eksplicitnim pozivom API funkcija koje *task* stavljaju o ovo stanje.
    - *Task* izlazi iz ovog stanja samo eksplicitnim pozivom API funkcija koje vraćaju *task* u stanje *Ready*.

> [!NOTE]
> U okviru FreeRTOS-a *task* koji je u stanju *Blocked* ima ***timeout period***. Nakon isteka ovog vremena, *task* će biti odblokiran čak i ako događaj na koji *task* čeka nije generisan."Beskonačno blokiranje" se može realizovati tako što će *timeout* biti "beskonačan"

Neke od najčešće korišćenih API funkcija FreeRTOS-a koje su neophodne za rad sa *task*-ovima:

| Funkcija      | Opis                                            |
| ------------- | ----------------------------------------------- |
| `xTaskCrate`  | Kreira *task*                                   |
| `vTaskDelete` | Briše *task*                                    |
| `vTaskDelay`  | Blokira pozivajući *task* određeni period vremena |

**Kreiranje *task*-ova** se vrši koristeći `xTaskCreate` funkciju koja ima sledeću deklaraciju:

```c
BaseType_t xTaskCreate(TaskFunction_t pvTaskCode,
                       const char * const pcName,
                       uint16_t usStackDepth,
                       void* pvParameters,
                       UBaseType_t uxPriority,
                       TaskHandle_t *pxCrateTask);
```

| Parametar       | Opis                         |
| ----------------| ---------------------------- |
| `pvTaskCode`    | Prethodno kreirana *task* funkcija |
| `pcName`        | Naziv *task*-a |
| `usStackDepth`  | Veličina steka koja se dodeljuje *task*-u (jedinica je širina procesorske reči u bajtovima) |
| `pvParameters`  | Parametar koji prilikom pokretanja *task* želimo da prosledimo *task*-u |
| `uxPriority`    | Prioritet *task*-a |
| `pxCreatedTask` | Instanca kreiranog *task*-a (implicitno predstavlja pokazivač na kreirani *task*) |

Ukoliko je *task* uspešno kreiran vraća se `pdPASS` dok se u suprotnom vraća `pdFALSE`. Prilikom realizacije softvera obavezno proveravati šta vraća ova funkcija.

**Brisanje kreiranog *task*-a** se vrši koristeći `vTaskDelete` funkciju koja ima sledeću deklaraciju:

```c
void vTaskDelete(TaskHandle_t pxTask);
```

| Parametar       | Opis |
| --------------- | ---- |
| `pxTask`        | Instanca *task*-a koji brišemo. Ukoliko prosledimo NULL parametar to podrazumeva da funkciju pozivamo iz *task*-a koji želimo da brišemo |

**Blokiranje *task*-a** na određeni period se realizuje koristeći `vTaskDelay` funkciju:

```c
void vTaskDelay(TickType_t xTicksToDelay);
```

| Parametar       | Opis |
| --------------- | ---- |
| `xTicksToDelay` | Broj tikova (poziva prekidnih rutina sistemskog tajmera) koliko želimo da *task* bude blokiran |

## Semafori

Za **signalizaciju događaja** u sistemu koriste se neki od sledećih mehanizama:

- semafor
- notifikacija
- grupa događaja

Za **komunikaciju** sa *task*-om koriste se neki od sledećih mehanizama:

- mehanizam deljene memorije
- mehanizam prosleđivanja poruka

Semafori se koriste kako bi se signalizirala pojava nekog događaja. Dva tipa semafora koja se koriste za signalizaciju su:

- **binarni semafor** - najčešće se koriste za sinhronizaciju i signaliziranje događaja i predstavljaju poseban tip brojačkih semafora

- **brojački semafor** - najčešće se koriste za pristup resursu koji ima ograničen broj paralelnih pristupa i nakon kreiranja, dodeljuje mu se inicijalna vrednost brojanja

> [!NOTE]
> U okviru template projekta potrebno je uključiti `semphr.h` header fajl ukoliko želimo da koristimo API funkcije FreeRTOS-a za rad sa semaforima.

| Funkcija                  | Opis                    |
| ------------------------- | ----------------------- |
| `xSemaphoreCreateBinary`  | Kreira binarni semafor  |
| `xSemaphoreCreateCounting`| Kreira brojački semafor |
| `xSemaphoreTake`          | Zauzima semafor         |
| `xSemaphoreGive`          | Oslobađa semafor        |
| `vSemaphoreDelete`        | Briše semafor           |

**Binarni semafor** se kreira pozivajući API funkciju FreeRTOS-a koja ima sledeću deklaraciju:

```c
SemaphoreHandle_t xSemaphoreCreateBinary(void);
```

Semafor je kreiran kao "prazan" što znači da prvo mora da se oslobodi (koristeći API funkciju `xSemaphoreGive`) pre nego što ga neko zauzme (koristeći API funkciju `xSemaphoreTake`). Ukoliko je semafor uspešno kreiran vraća se instanca `SemaphoreHandle_t` strukture dok se u suprotnom vraća `NULL`.

**Brojački semafor** se kreira pozivajući API funkciju FreeRTOS-a koja ima sledeću deklaraciju:

```c
SemaphoreHandle_t xSemaphoreCreateCounting(UBaseType_t uxMaxCount, UBaseType_t uxInitialCount);
```

| Parametar        | Opis |
| ---------------  | ---- |
| `uxMaxCount`     | Maksimalan broj do kojeg semafor može da broji. Kada se dostigne ova vrednost, semafor više ne može da se oslobađa |
| `uxInitialCount` | Početna vrednost brojača |

Ukoliko je semafor uspešno kreiran vraća se instanca `SemaphoreHandle_t` strukture dok se u suprotnom vraća `NULL`.

Iste API funkcije za zauzimanje i oslobađanje semafora se koriste bez obzira da li je u pitanju binarni ili brojački semafor.

Semafor se zauzima pozivajući API funkciju FreeRTOS-a koja ima sledeću deklaraciju:

```c
BaseType_t xSemaphoreTake(SemaphoreHandle_t xSemaphore, TickType_t xTicksToWait);
```

| Parametar      | Opis |
| -------------- | ---- |
| `xSemaphore`   | Instanca prethodno kreiranog semafora koji se zauzima |
| `xTicksToWait` | Maksimalan broj tikova koliko *task* može da se blokira čekajući da semafor postane dostupan |

Funkcija vraća `pdPASS` ako je semafor uspešno zauzet a `pdFAIL` ukoliko zauzimanje semafora nije uspešno urađeno. Funkcija se poziva isključivo iz *task*-a

Semafor se oslobađa pozivajući API funkciju FreeRTOS-a koja ima sledeću deklaraciju:

```c
BaseType_t xSemaphoreGive(SemaphoreHandle_t xSemaphore);
```

| Parametar      | Opis |
| -------------- | ---- |
| `xSemaphore`   | Instanca prethodno kreiranog semafora koji se oslobađa |

Funkcija vraća `pdPASS` ako je semafor uspešno oslobođen, a `pdFAIL` ukoliko oslobađanje semafora nije uspešno urađeno.

## Prekidi

Mehanizam prekida je u potpunosti isti bez obzira da li ste koristili neki RTOS ili pisali *Bare-Metal* softver.

> [!NOTE]
> Potrebno je napomenuti da nije moguće blokiranje ISR jer je to svojstvo *task*-ova (softverskog dela).

U okviru FreeRTOS-a postoje dve vrste API funkcija:

- One koje se pozivaju **iz konteksta *task*-a**

- One koje se pozivaju **iz konteksta prekidne rutine** (*Interrupt safe API functions*)
    - Kako bi povećali vremensku efikasnost funkcija koje se pozivaju iz konteksta *task*-a, a za koje postoji potreba da se pozivaju i iz prekidne rutine, uvedene su posebne funkcije.
    - Da funkcije nisu razdvojene postojao bi veliki *overhead* kada se neka API funkcija poziva iz prekidne rutine što nije dobro jer ISR treba da bude što kraća i efikasnija.

API funkcije FreeRTOS-a koje se mogu koristiti iz konteksta prekidne rutine imaju isti naziv kao API funkcije koje se mogu koristiti iz konteksta *task*-a ali je na kraju naziva funkcije dodat sufiks `FromISR`.

Ekvivalenti FreeRTOS API funkcija `xSemaphoreGive` i `xSemaphoreTake` u prekidnoj rutini su:

```c
BaseType_t xSemaphoreGiveFromISR(xSemaphore, pxHigherPriorityTaskWoken);

BaseType_t xSemaphoreTakeFromISR(xSemaphore, pxHigherPriorityTaskWoken);
```

| Parametar                   | Opis |
| --------------------------- | ---- |
| `xSemaphore`                | Instanca prethodno kreiranog semafora koji se oslobađa |
| `pxHigherPriorityTaskWoken` | ...  |

U okviru konteksta prekida se ne vrši automatska zamena konteksta već se prosleđuje informacija o tome da li je potrebno izvršiti zamenu konteksta. **Opcioni** parametar `pxHigherPriorityTaskWoken` koji funkcija setuje na vrednost `pdTRUE` ukoliko postoji potreba da se izvrši zamena konteksta (odnosno poziv *Scheduler*-a) odmah nakon završetka prekidne rutine, u suprotnom funkcija setuje vrednost `pdFALSE`.

> [!IMPORTANT] 
> Ako želimo da FreeRTOS *Interrupt safe* API funkcija modifikuje vrednost ovog parametra u zavisnosti od toga da li treba izvršiti zamenu konteksta ili ne, pre poziva API funkcije u okviru prekidne rutine vrši se inicijalizacija `BaseType_t xTaskWoken = pdFALSE`.  
> 
> Ako želimo da se u nakon završetka prekidne rutine izvrši zamena konteksta onda se na kraju prekidne rutine poziva `portYIELD_FROM_ISR(xTaskWoken)`.
>   - ako je vrednost parameter setovana na `pdTRUE` vrši se zamena konteksta
>   - ako je vrednost parameter setovana na `pdFALSE` ne vrši se zamena konteksta.
>
> Ako nam vrednost `pxHigherPriorityTaskWoken` parametar nije bitan, onda se prosleđuje vrednost `NULL`.

## Deljena memorija i *mutex* semafori

Pod **deljenom memorijom** podrazumevamo deo adresnog prostora platforme kome se pristupa iz dva ili više *task*-ova. Deljena memorija se može koristiti kao jedan vid komunikacije među *task*-ovima u sistemu.

***Mutex* semafori** omogućavaju atomičnost operacije nad deljenom memorijom u okviru softvera baziranog na RTOS. Kada koristimo neki oblik deljene memorije treba joj dodeliti *Mutex* semafor koji omogućava da u jednom posmatranom trenutku samo jedan *task* ima pristup deljenoj memoriji (*Consumer* ili *Producer*).

Ukoliko *task* pokuša da pristupi deljenoj memoriji dok neki drugi *task* obavlja operaciju nad deljenom memorijom, *task* će se blokirati. *Task* će se odblokirati onda kada *task*, koji je zauzeo *mutex* semafor, oslobodi *mutex* semafor.

*Mutex* semafori podržavaju mehanizam inverzije prioriteta. Sprečavaju da se *task* manjeg prioriteta izvrši ukoliko je *task* većeg prioriteta blokiran na *mutex*-u.

> [!IMPORTANT] 
> Onaj ko je uzeo *mutex* semafor mora taj semafor i da oslobodi. Ovo nije slučaj sa binarnim semaforom. Binarni semafor se koristi za signaliziranje događaja dok se *mutex* se koristi kako bi se ostvarila atomičnost kritičnih sekcija u kodu.

Kako bi omogućili korišćenje *mutex* semafora u okviru `FreeRTOSConfig.h` fajla moramo podesiti sledeći makro:

```c
#define configUSE_MUTEXES 1 
```

Prvi korak pri radu sa *mutex* semaforom jeste da izvršimo kreiranje *mutex* semafora korišćenjem sledeće API funkcije:

```c
SemaphoreHandle_t xSemaphoreCrateMutex(void);
```

Ukoliko prilikom kreiranja funkcija vrati `NULL` to znači da semafor nije uspešno kreiran (verovatno zbog nedostatka resursa u sistemu), u suprotnom *mutex* semafor uspešno kreiran i da ga možemo koristiti.

Funkcije za zauzimanje i oslobađanje *mutex* semafora su iste kao i funkcije za zauzimanje i oslobađanje binarnog semafora.

## Softverski tajmeri

**Softverski tajmeri** se u FreeRTOS-u koriste kako bi se zakazalo izvršavanje neke funkcionalnosti u određenom vremenskom trenutku ili u slučaju da je potrebno periodično izvršavanje određene funkcionalnosti.

Period softverskog tajmera je vreme proteklo od trenutka startovanja tajmera do trenutka početka izvršavanja tajmerske *callback* funkcije. Postoje dve vrste softverskih tajmera u FreeRTOS-u:

- ***One-shot timer*** - jednom kada se startuje tajmerska *callback* funkcija se poziva samo jednom nakon isteka periode tajmera
- ***Auto-reload timer*** - jednom kada se startuje tajmerska *callback* funkcija se poziva periodično nakon isteka tajmera.

Funkcionalnost softverskog tajmera je opciona u FreeRTOS-u. Ukoliko želimo da koristimo ovu 
funkcionalnost neophodno je:

1. U okviru projekta uključiti FreeRTOS source fajl pod nazivom `timers.c` 

```c
#include "timers.c"
```

2. U `FreeRTOSConfig.h` fajlu setovati `configUSE_TIMERS` makro na vrednost `1`

```c
#define configUSE_TIMERS 1
```

Funkcija koja se izvršava od strane softverskog tajmera naziva se tajmerska *callback* funkcija. Funkcionalnost ove funkcije definiše korisnik, ne vraća vrednost i kao jedini argument prima instancu tajmera `TimerHandle_t` kome je ova funkcija dodeljena (koji je pozvao ovu *callback* funkciju).

```c
void ATimerCallback(TimerHandle_t xTimer);
```

> [!NOTE]
> Funkcionalnost koju tajmerska *callback* funkcija realizuje mora biti jednostavna kako bi se što pre izvršila.

Tajmerska callback funkcija se izvršava iz konteksta FreeRTOS sistemskog "Deamon" (pozadinskog) *task*-a. Vrednošću `configTIMER_TASK_PRIORITY` makroa u `FreeRTOSConfig.h` fajlu setujemo prioritet "Deamon" *task*-a. Vrednošću `configTIMER_TASK_STACK_DEPTH` makroa u `FreeRTOSConfig.h` fajlu setujemo veličinu steka koju želimo da dodelimo ovom *task*-u. 

U slučaju kontrole funkcionalnosti tajmera (start, stop, reset, ...), "Deamon" *task* čita komande iz **tajmerskog *queue*-a**. Kreira se automatski pri startovanju FreeRTOS *Scheduler*-a, a dužina ovog *queue*-a određena je vrednošću `configTIMER_QUEUE_LENGTH` makroa u `FreeRTOSConfig.h` fajlu.

> [!WARNING]
> Iz tajmerske *callback* funkcije se ne smeju pozivati FreeRTOS api funkcije koje mogu izazvati blokiranje *task*-a. U tom slučaju bi došlo do blokiranja "Deamon" *task*-a.

Pre korišćenja mora se kreirati softverski tajmer, on se može kreirati pre startovanja *Scheduler*-a ili iz konteksta *task*-a.

```c
TimerHandle_t xTimerCreate(const char * const pcTimerName
                           TickType_t xTimerPeriodInTicks,
                           UBaseType_t uxAutoReload,
                           void* pvTimerID,
                           TimerCallbackFunction_t pxCallbackFunction);
```

| Parametar             | Opis |
| --------------------- | ---- |
| `pcTimerName`         | Naziv tajmera. |
| `xTimerPeriodInTicks` | Period tajmera izražen u sistemskim tikovima. Ukoliko želimo da umesto sistemskih tikova definišemo apsolutno vreme u ms, možemo iskoristiti makro funkciju `pdMS_TO_TICKS` koja prima vrednost u ms-ma i vraća odgovarajući broj u sistemskim tikovima. |
| `uxAutoReload`        | Ukoliko je vrednost ovog parametra `pdTRUE` kreira se auto-reload softverski tajmer. Ukoliko je vrednost ovog parametra `pdFALSE` kreira se one-shot softverski tajmer. |
| `pvTimerID`           | Svakom kreiranom tajmeru se dodeljuje jedinstvena vrednost. Posredstvom ovog parametra može se dohvatiti ta vrednost. |
| `pxCallbackFunction`  | Prethodno definisana tajmerska *callback* funkcija.

Tajmer se kreira u neaktivnom stanju. Startovanje softverskog tajmera realizuje se korišćenjem sledeće API funkcije:

```c
BaseType_t xTimerStart(TimerHandle_t xTimer, TickType_t xTicksToWait);
```

| Parametar      | Opis |
| -------------- | ---- |
| `xTimer`       | Instanca prethodno kreiranog tajmera |
| `xTicksToWait` | Broj sistemskih tikova koje će *task* provesti u blokiranom stanju ukoliko nije moguće startovati tajmer |

Ukoliko je komanda "startuj tajmer" uspešno poslata u tajmerski *queue* funkcija vraća `pdPASS`, a suprotnom vraća `pdFALSE`. Ukoliko se tajmer startuje iz prekidne rutine potrebno je koristiti `xTimerStartFromISR`.

Zaustavljanje softverskog tajmera realizuje se korišćenjem sledeće API funkcije:

```c
BaseType_t xTimerStop(TimerHandle_t xTimer, TickType_t xTicksToWait);
```

| Parametar      | Opis |
| -------------- | ---- |
| `xTimer`       | Instanca prethodno kreiranog tajmera |
| `xTicksToWait` | Broj sistemskih tikova koje će *task* provesti u blokiranom stanju ukoliko nije moguće zaustaviti tajmer |

Ukoliko je komanda "zaustavi tajmer" uspešno poslata u tajmerski *queue* funkcija vraća `pdPASS`, a u suprotnom vraća `pdFALSE`. Ukoliko se tajmer zaustavlja iz prekidne rutine potrebno je koristiti `xTimerStopFromISR`.

## *Queue*

Jedan od načina da se realizuje komunikacija između *task*-ova, ali i između *task*-ova i prekidne rutine, jeste korišćenjem objekta kernela RTOS pod nazivom ***Queue***. To je zapravo FIFO struktura tj. podaci se dodaju na kraj reda a čitaju se sa početka reda (*Thread-safe* struktura).

Komunikacija bazirana na korišćenju *queue*-a podrazumeva da postoji neko (*task* ili ISR) koji upisuje elemente u *queue* (*producer*) i da postoji neko (*task* ili ISR) ko čita ono što je upisano u *queue* (*consumer*). Može da postoji više *producer*-a i više *consumer*-a koji koriste isti *queue*.

Pri radu sa queue-om kao prvi korak neophodno je kreirati *queue*. Obično se prilikom kreiranja 
specificiraju vrednosti dva parametra:
- ***queue item size*** - veličina jednog elementa unutar *queue*-a
- ***queue length*** - maksimalan broj elemenata koji može biti unutar *queue*-a

Elementi *queue*-a mogu biti različiti tipovi podataka:
- ugrađeni tipovi podataka (int, char, ...)
- korisnički definisani tipovi podataka (strukture)

> [!NOTE]
> Ukoliko u *queue* upisujemo "složenije" poruke preporučljivo je kreirati strukturu, instancirati objekat te strukture, inicijalizovati polja tog objekta i upisati ga u *queue*.

Upisivanje podataka u *queue* vrši se na jedan od dva načina:

- Umesto sadržaja podatka u *queue* se upisuje pokazivač na podatak (prosleđivanje po referenci).
Brži upis ali moramo čuvati podatak na predajnoj strani sve dok ga prijemna strana ne obradi.

- Kopiranje sadržaja podatka u *queue* (prosleđivanje po referenci). Sporiji upis ali čim smo podatak upisali u *queue* ne moramo više da brinemo o njemu.

Blokiranje taska koji vrši operaciju nad queue-om je moguće:

- Ukoliko se upisuje u pun *queue* (*task* će se odblokirati kada *consumer* pročita prvu poruku)

- Ukoliko čita iz praznog *queue*-a (*task* će se odblokirati kada *producer* upiše prvu poruku)

Dakle, pored toga što se *queue* može koristiti kako bi se ostvarila **komunikacije** *queue* se može koristiti i kako bi se ostvarila i **sinhronizacija** između taskova koji čekaju na neki podatak.

Kao prvi korak u procesu korišćenja *queue*-a neophodno je kreirati *queue* koji se kreira pozivom sledeće FreeRTOS API funkcije:

```c
QueueHandle_t xQueueCreate(UBaseType_t uxQueueLength, UBaseType_t uxItemSize);
```

| Parametar        | Opis |
| ---------------- | ---- |
| `uxQueueLength`  | Maksimalan broj elemenata u *queue*-u |
| `uxItemSize`     | Veličina jednog elementa u okviru *queue*-a |

Ukoliko postoje problemi sa kreiranjem *queue*-a vraća se `NULL`, najčešće problem postoji zbog nedovoljne memorije na platformi. Ukoliko je *queue* uspešno kreiran vraća se instanca strukture (*handler*) `QueueHandle_t` koja se koristi kako bi se pristupilo kreiranom *queue*-u.

Upis u *queue* je moguće realizovati posredstvom jedne od dve funkcije

- Funkcijom koja dodaje elemente **na početak reda**:

```c
BaseType_t xQueueSendToFront(QueueHandle_t xQueue,
                             const void* pvItemToQueue,
                             TickType_t xTicksToWait);
```

- Funkcijom koja dodaje elemente **na kraj reda**:

```c
BaseType_t xQueueSendToBack(QueueHandle_t xQueue,
                            const void* pvItemToQueue,
                            TickType_t xTicksToWait);
```

| Parametar        | Opis |
| ---------------- | ---- |
| `xQueue`         | Instanca prethodno kreiranog *queue*-a |
| `pvItemToQueue`  | Pokazivač na podatak koji će biti kopiran u queue |
| `xTicksToWait`   | Ukoliko je *queue* pun ovim parametrom se specificira koliko vremena će *task* provesti u blokiranom stanju |

Funkcije vraćaju `pdPASS` ukoliko je element uspešno kopiran u *queue*. Ukoliko je *queue* pun i isteklo je vreme koje je specificirano da *task* provede u blokiranom stanju funkcije vraćaju `errQUEUE_FULL`.

Ukoliko se funkcije pozivaju iz konteksta prekidne rutine potrebno je koristiti njihove implementacije koje se završavaju sa `FromISR` (`xQueueSendToBackFromISR` i `xQueueSendToFromFromISR`).

Čitanje iz *queue*-a je moguće korišćenjem sledeće funkcije:

```c
BaseType_t xQueueReceive(QueueHandle_t xQueue, 
                         void * const pvBuffer, 
                         TickType_t xTicksToWait);
```

Funkcija vraća `pdPASS` ukoliko je element uspešno pročitan. Ukoliko je *queue* prazan i isteklo je vreme koje je specificirano da *task* provede u blokiranom stanju funkcija vraća `errQUEUE_EMPTY`.

Ukoliko se funkcije poziva iz konteksta prekidne rutine potrebno je koristiti njenu implementaciju koja se završava sa `FromISR` (`xQueueReceiveFromISR`).

## Grupa događaja

**Grupa događaja** predstavlja mehanizam signalizacije pojave jednog ili više događaja karakterističan za FreeRTOS.

Mehanizam "Grupa događaja" omogućava:
- Sinhronizaciju više *task*-ova
- Broadcasting događaja na više *task*-ova
- Blokiranje jednog ili više *task*-ova do trenutka generisanja jednog ili kombinacije događaja  
- Redukovanje količine memorije koja se koristi od strane FreeRTOS-a jer više semafora, koji su korišćeni za signalizaciju više događaja, sada možemo zameniti samo jednom instancom grupe događaja.

> [!NOTE]
> Ukoliko želimo da koristimo grupu događaja potrebno je u okviru projekta kompajlirati fajl `event_groups.c`.

Grupa događaja je realizovana kao niz boolean vrednosti. Informacija o pojavi nekog događaja (stanje događaja) čuva se u okviru jednog bita (*Event flag*). Vrednost 1 označava da je došlo do generisanja događaja dok vrednost 0 označava da se događaj nije generisao. Ove binarne vrednosti koje čuvaju stanje događaja su deo promenljive tipa `EventBits_t`. Pri projektovanju softvera neophodno je svakom od bita dodeliti odgovarajuće značenje.

Broj događaja koji se čuvaju u okviru jedne promenljive tipa `EventBits_t` zavisi od toga da li je setovan `configUSE_16_BIT_TICKS`.

```c
#define configUSE_16_BIT_TICKS 1 // koristi se 8 bita  
#define configUSE_16_BIT_TICKS 0 // koristi se 24 bita
```

Kreiranje grupe događaja se realizuje pozivom sledeće API funkcije:

```c
EventGroupHandle_t xEventGroupCreate(void);
```

Ukoliko nije moguće kreirati grupu događaja ova funkcija vraća `NULL`. Ukoliko je grupa događaja uspešno kreirana ova funkcija vraća instancu tipa `EventGroupHandle_t` koja se koristi za pristup grupi događaja.

Setovanje jednog ili više bita u okviru grupe događaja realizuje se pozivom sledeće API funkcije

```c
EventBits_t xEventGroupSetBits(EventGroupHandle_t xEventGroup, const EventBits_t uxBitsToSet);
```

| Parametar     | Opis |
| ------------- | ---- |
| `xEventGroup` | Instanca prethodno kreirane grupe događaja |
| `uxBitsToSet` | Binarna maska koja specificira koje bite u okviru grupe bita treba setovati na 1 |

Funkcija vraća sadržaj koju promenljiva tipa `EventBits_t`, unutar grupe događaja, ima u trenutku poziva ove funkcije.

> [!WARNING]
> Povratna vrednost ne mora imati one bite koji su specificirani promenljivom `uxBitsToSet` setovane na 1.

Čekanje da jedan ili više bitova budu setovani na 1, od stane drugog taska ili prekidne rutine, realizuje se pozivom sledeće API funkcije:

```c
EventBits_t xEventGroupWaitBits(const EventGroupHandle_t xEventGroup, 
                                const EventBits_t uxBitsToWaitFor,
                                const BaseType_t xClearOnExit,
                                const BaseType_t xWaitForAllBits
                                TickType_t xTicksToWait);
```

| Parametar         | Opis |
| ----------------- | ---- |
| `xEventGroup`     | Instanca prethodno kreirane grupe događaja. |
| `uxBitsToWaitFor` | Binarna maska koja specificira bite u grupi događaja na koje čekamo da budu setovani na vrednost 1. |
| `xClearOnExit`    | Ovaj parametar može imati dve vrednosti: pdTRUEili pdFALSE. Ukoliko ovaj parametar ima vrednost pdTRUEizvršiće se setovanje bita, definisanih maskom uxBitsToWaitFor,  na vrednost 0. Ukoliko ovaj parametar ima vrednost pdFALSE biti ostaju 
nepromenjeni. |
| `xWaitForAllBits` | Ovaj parametar može imati dve vrednosti: `pdTRUE` ili `pdFALSE`. Ukoliko ovaj parametar ima vrednost `pdTRUE` *task* će ostati u stanju "*Blocked*" dok svi biti,definisani maskom uxBitsToWaitFor, ne budu setovani na 1. Ukoliko je vrednost ovog parametra `pdFALSE` *task* će ostati u stanju "*Blocked*" dok bar jedan od bita, definisanih maskom `uxBitsToWaitFor`, ne budu setovani na vrednost 1 |
| `xTicksToWait`    | Vreme koje će *task* provesti u stanju "*Blocked*" čekajući da se neki (ili svi) biti setuju na vrednost 1 |

Ukoliko se iz funkcije izlazi kao posledica setovanja barem jednog bita (ili svih bita) definisanih maskom `uxBitsToWaitFor`, funkcija vraća vrednost koju je grupa događaja imala u trenutku kada su se stvorili uslovi da *task*, koji čeka na bite, bude odblokiran. U slučaju da je `xClearOnExit` parametar setovan funkcija vraća vrednost neposredno pre setovanja bita na vrednost 0. Ukoliko se iz funkcije izlazi kao posledica isteka vremenskog intervala definisanog parametrom `xTicksToWait`, funkcija vraća vrednost koju grupa događaja ima u tom trenutku.

Setovanje jednog ili više bita u okviru grupe događaja, iz prekidne rutine, realizuje se pozivom sledeće API funkcije:

```c
EventBits_t xEventGroupSetBitsFromISR(EventGroupHandle_t xEventGroup, 
                                      const EventBits_t uxBitsToSet,
                                      BaseType_t pxHigherPriorityTaskWoken);
```

| Parametar                   | Opis |
| --------------------------- | ---- |
| `xEventGroup`               | Instanca prethodno kreirane grupe događaja |
| `uxBitsToSet`               | Binarna maska koja specificira koje bite u okviru grupe bita treba setovati na 1 |
| `pxHigherPriorityTaskWoken` | Ukoliko je vrednost ovog parametra setovana na `pdTURE` tada je potrebno izvršiti zamenu konteksta pre izlaska iz prekidne rutine |


## Mehanizam notifikacije

**Mehanizam notifikacije** *task*-a u FreeRTOS-u omogućava direktnu signalizaciju *task*-u da se desio neki događaj, ili direktnu komunikaciju sa taskom, bez upotrebe dodatnih objekata kernela (*queue*-ova, semafora, grupe događaja, ...).

Svaki kreirani *task* u FreeRTOS-u ima:
- notifikacionu vrednost (*notification value*) - 32-bitni neoznačeni broj
- notifikacioni status (*notification state*)
    - može imati vrednosti *"Pending"* i *"Not-Pending"*
    - kada *task* primi notifikaciju notifikacioni status uzima vrednost *"Pending"*. Kada task pročita notifikacionu vrednost, notifikaciono stanje uzima vrednost *"Not-Pending"*. 

Prednosti korišćenja mehanizma notifikacije

- Signalizacija pojave događaja ili slanje podatka *task*-u je značajno brže od korišćenja mehanizma semafora, *queue*-a ili grupe događaja

- Zauzeće memorije je manje u odnosu da mehanizam signalizacije ili komunikacije sa *task*-om realizujemo koristeći semafor, *queue*, ili grupu događaja 

Korišćenje mehanizma notifikacije nije uvek moguće zbog određenih ograničenja kojih moramo biti svesni kada pišemo softver baziran na FreeRTOS-u

- Nije moguće slanje podatka iz *task*-a u ISR (što je na primer moguće kada koristimo *queue*).

- Može postojati samo jedan *task* koji prima notifikaciju (kada koristimo grupu događaja možemo imati više *task*-ova koji primaju neku signalizaciju).

- Ne postoji mogućnost baferisanja podataka (što je na primer moguće kada koristimo *queue*).

- Ne postoji mogućnost implementacije *Broadcast*-a (što je na primer moguće kada koristimo grupu događaja).

- Ne postoji mogućnost blokiranja ako prethodno poslata notifikaciona vrednost nije obrađena (kada upisujemo u pun queue task koji upisuje se blokira dok se ne oslobodi jedno mesto u *queue*-u).

Kada se task kreira notifikaciona vrednost je inicijalizovana na nulu. Signaliziranje pojave događaja korišćenjem mehanizma notifikacije se realizuje upotrebom `xTaskNotifyGive` i `xTaskNotifyTakeFreeRTOS` API funkcija:

```c
BaseType_t xTaskNotifyGive(TaskHandle_t xTaskToNotify)
```

| Parametar       | Opis |
| --------------- | ---- |
| `xTaskToNotify` | Instanca prethodno kreiranog taska koja se može dohvatiti kada se *task* kreira koristeći `xTaskCreate` funkciju |

Funkcija `xTaskNotifyGive` inkrementira notifikacionu vrednost taska koji čeka notifikaciju i menja njegov notifikacioni status u "*Pending*" (ukoliko već nije u stanju "*Pending*"). Uvek vraća `pdPass`. U slučaju da se poziva iz konteksta prekidne rutine koristiti `xTaskNotifyGiveFromISR`.

```c
BaseType_t xTaskNotifyTake(BaseType_t xClearCountOnExit, TickType_t xTicksToWait);
```

| Parametar           | Opis |
| ------------------- | ---- |
| `xClearCountOnExit` | Ovaj parametar može imati vrednosti `pdTRUE` ili `pdFALSE`. Ukoliko parametar ima vrednost pdTRUEonda će se izvršiti setovanje notifikacione vrednosti na 0 pre izlaska iz funkcije. Ukoliko parametar ima vrednost `pdFALSE` i ako je notifikaciona vrednost veća od 0, onda se pri izlasku iz funkcije dekrementira notifikaciona vrednost |
| `xTicksToWait` | Broj sistemski tikova koliko će task provesti u blokiranom stanju čekajući da notifikaciona vrednost postane različita od 0 |

Funkcija `xTaskNotifyGive` vraća notifikacionu vrednost pre setovanja na 0 (u slučaju da je `xClearOnExit` setovan na `pdTRUE`) ili dekrementiranja (u slučaju da je `xClearOnExit` setovan na `pdFALSE`).

Dakle kombinacija `xTaskNotifyGive` i `xTaskNotifyTake` API funkcija pruža istu funkcionalnost kao mehanizam semafora.

Kombinacija API funkcija koje pružaju mogućnost fleksibilnijeg korišćenja mehanizma notifikacije su `xTaskNotify` i `xTaskNotifyWait`:

```c
BaseType_t xTaskNotify(TaskHandle_t xTaskToNotify, uint32_t ulValue, eNotifyAction eAction)
```

| Parametar           | Opis |
| ------------------- | ---- |
| `xTaskToNotify` | Instanca taska koji želimo da notifikujemo |
| `xTicksToWait`  | Način na koji se ova vrednost koristi zavisi od `eAction` parametra |
| `eAction`       | Uzima vrednost iz predefinisanog skupa vrednosti |

Skup vrednosti `eAction`-a:
- `eNoAction` – Vrši se isključivo notifikacija taska bez modifikacije notifikacione vrednosti. `ulValue` se ignoriše.
- `eSetBits` - Parametar ulValue predstavlja masku koja definiše koji biti će se setovati. Ova funkcionalnost nudi mogućnost implementacije jednostavnije grupe događaja
- `eIncrement` – Notifikaciona vrednost se inkrementira za 1. `ulValue` se ignoriše.
- `eSetValueWithOverwrite` – Notifikaciona vrednost uzima vrednost definisanu parametrom ulValue. Ne posmatra se notifikacioni status.
- `eSetValueWithoutOverwrite` - Notifikaciona vrednost uzima vrednost definisanu parametrom `ulValue` samo ukoliko je notifikacioni status "*Not-Pending*". Ukoliko je notifikacioni status "*Pending*" dodela notifikacioni vrednosti nije moguća i funkcija vraća `pdFALSE`.

Primetiti da funkcija isključivo u jednom slučaju vraća `pdFALSE` u svim ostalima `pdTRUE`. U slučaju da se funkcija poziva iz konteksta prekidne rutine koristiti `xTaskNotifyFromISR`.


```c
BaseType_t xTaskNotifyWait(uint32_t ulBitsToClearOnEntry,
                           uint32_t ulBitsToClearOnExit,
                           uint32_t* pulNotificationValue,
                           TickType_t xTicksToWait)
```

| Parametar           | Opis |
| ------------------- | ---- |
| `ulBitsToClearOnEntry` | Maska koja definiše koje bite notifikacione vrednosti ćemo brisati na ulazu u funkciju. Može se koristiti makro `ULONG_MAX` za masku `0xFFFFFFFF` |
| `ulBitsToClearOnExit`  | Maska koja definiše koje bite notifikacione vrednosti ćemo brisati na izlasku iz funkcije. Može se koristiti makro `ULONG_MAX` za masku `0xFFFFFFFF` |
| `pulNotificationValue` | Notifikaciona vrednost pre brisanja. Ukoliko ne koristimo možemo proslediti `NULL`  |
| `xTicksToWait`         | Broj sistemski tikova koliko će task provesti u blokiranom stanju čekajući da notifikaciona vrednost postane različita od 0  |

Skup vrednosti `eAction`-a:
- `eSetValueWithoutOverwrite` – Vrši se isključivo notifikacija taska bez modifikacije notifikacione vrednosti. `ulValue` se ignoriše.
- `eSetBits` - Parametar ulValue predstavlja masku koja definiše koji biti će se setovati. Ova funkcionalnost nudi mogućnost implementacije jednostavnije grupe događaja
- `eIncrement` – Notifikaciona vrednost se inkrementira za 1. `ulValue` se ignoriše.
- `eSetValueWithOverwrite` – Notifikaciona vrednost uzima vrednost definisanu parametrom ulValue. Ne posmatra se notifikacioni status.

> [!IMPORTANT]
> Da bi korišćenje mehanizma notifikacije u FreeRTOS-u bilo moguće neophodno je setovati makro `configUSE_TASK_NOTIFICATIONS` na vrednost 1.
