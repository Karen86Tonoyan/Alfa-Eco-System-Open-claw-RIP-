# ALFA Proof Repo

`ALFA` to warstwa kontroli nakładana na istniejące LLM-y. Dodaje routing, ocenę ryzyka, nadzorowaną egzekucję, audyt oraz wyraźny podział między voice, decyzją, pamięcią i wykonaniem.

To repozytorium jest **publicznym proof repo**. Pokazuje, że warstwa kontrolna działa naprawdę: filtry, execution gate i scenariusze demo są realne. Nie publikuje jednak pełnego operacyjnego rdzenia.

## Co to repo udowadnia

- `Filtry Tonoyana` można zapisać jako pipeline decyzyjny, a nie tylko jako narrację.
- `Voice -> Brain -> Filters -> Cerber -> Plugin/Response` działa jako spójny przepływ.
- System jest przygotowany do działania zarówno `lokalnie (Ollama)`, jak i `w chmurze`.
- Warstwa nadzoru potrafi dopuścić, zablokować, doprecyzować albo eskalować działanie zanim dojdzie do wykonania.

## Publiczne pozycjonowanie

`ALFA to gotowa warstwa kontroli, którą można nałożyć na istniejące LLM-y.`

Repo jest celowo selektywne:

- Publiczne: architektura, kod proof layer, demo, testy i publiczne wrappery.
- Prywatne / B2B: produkcyjne policy sety, logika egzekucji, wrażliwe connectory, fallback chain i krytyczne mechanizmy enforcement.

Celem jest wiarygodność bez oddawania pełnego rdzenia wykonawczego.

## Główne warstwy

- `Voice` normalizuje wejście głosowe i wake word.
- `Brain` odpowiada za intencję, ryzyko, routing i stan.
- `Filters` tłumaczą empatię, niejednoznaczność i intencję na strukturę decyzyjną.
- `Cerber` jest execution gate przed każdym pluginem.
- `Plugins` są narzędziami o ograniczonych uprawnieniach, a nie wolnymi agentami.
- `Memory` rozdziela pamięć sesji, użytkownika, systemu, cache i audyt.
- `Backends` pokazują gotowość na tryb lokalny i chmurowy bez ujawniania prywatnej orkiestracji.

## Tryby wdrożenia

- `Ollama` jako podgląd lokalnego kanału modelowego.
- `Cloud` jako podgląd zarządzanego kanału modelowego.

Publiczne repo pokazuje granice i interfejsy. Produkcyjny routing i prywatne integracje pozostają poza tym drzewem.

## Szybki start

```powershell
python .\alfa_demo.py
python -m pytest .\tests -q
```

## Model IP i dostępu

To repo działa w modelu `source-available / B2B-first`.

- Publiczny kod służy do oceny, demonstracji i due diligence.
- Prawa autorskie, znaki, metodologia i know-how pozostają chronione.
- Głębsze moduły są udostępniane wyłącznie w modelu partnerskim lub komercyjnym.

Zobacz:

- [IP_AND_ACCESS_MODEL](IP_AND_ACCESS_MODEL.md)
- [SECURITY_DISCLOSURE_BOUNDARY](SECURITY_DISCLOSURE_BOUNDARY.md)
- [VALIDATED_LINEAGE](VALIDATED_LINEAGE.md)

`Bezpieczeństwo, IP i realna kontrola operacyjna są ważniejsze niż sam rozgłos.`

