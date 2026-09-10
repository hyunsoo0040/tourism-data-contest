import { useId, type ReactNode } from "react";

import { sourceAttribution, type SourceObservation, type TripContextPlace } from "../../api/trip-context";
import { FACILITY_CHOICES } from "../journey/groundedTrip";

function facilityLabel(key: string): string | undefined {
  return FACILITY_CHOICES.find((choice) => choice.id === key)?.label;
}

export function hasConfirmedValue(fact: SourceObservation): boolean {
  return fact.state === "SUPPORTED_FACT" && fact.value !== null
    && (typeof fact.value !== "string" || fact.value.trim().length > 0);
}

export function visibleFacilityFacts(place?: TripContextPlace): SourceObservation[] {
  if (!place || place.state === "UNAVAILABLE") return [];
  return place.facts.filter((fact) => fact.claim === "FACILITY" && facilityLabel(fact.key)
    && hasConfirmedValue(fact));
}

function FacilityObservation({ observation }: { observation: SourceObservation }) {
  const state = observation.value === true ? "있음"
      : observation.value === false ? "없음" : String(observation.value);
  return (
    <div data-trip-fact={observation.key} data-support-state={observation.state}>
      <dt>{facilityLabel(observation.key)}</dt>
      <dd>
        <strong className="tourism-fact-value">{state}</strong>
        {observation.reference_date && <p className="operating-information-meta">{observation.reference_date} 기준</p>}
      </dd>
    </div>
  );
}

/** Source-bound facility panel; temporal/route/regional panels compose as children. */
export function TripContext({ place, loading, checkedAt, mode, children }: {
  place?: TripContextPlace;
  loading: boolean;
  checkedAt?: string;
  mode?: "PINNED" | "REFRESHED";
  children?: ReactNode;
}) {
  const headingId = useId();
  const facts = loading ? [] : visibleFacilityFacts(place);
  const sources = [...new Set(facts.flatMap((fact) => fact.evidence.map((entry) => entry.receipt.service)))];
  const notes = [...new Set(facts.map((fact) => fact.reason.trim()).filter(Boolean))];
  if (facts.length === 0) return children ? <>{children}</> : null;
  return (
    <section className="tourism-info-card" aria-labelledby={headingId} data-trip-context-state={place?.state}>
      <h3 id={headingId}>편의시설</h3>
      <dl className="operating-information-list tourism-facts">
        {facts.map((fact) => <FacilityObservation key={fact.key} observation={fact} />)}
      </dl>
      {notes.map((note) => <p className="tourism-note" key={note}>{note}</p>)}
      {sources.length > 0 && <p className="tourism-source">{sources.map((service, index) => {
        const attribution = sourceAttribution(service);
        return <span key={service}>{index > 0 && " · "}<a href={attribution.url} target="_blank" rel="noreferrer">{attribution.label}</a></span>;
      })}</p>}
      {checkedAt && <p className="operating-information-meta">
        {mode === "PINNED" ? "추천 당시 확인한 정보" : "추가로 확인한 정보"} · <time dateTime={checkedAt}>
          {new Intl.DateTimeFormat("ko-KR", { timeZone: "Asia/Seoul", year: "numeric", month: "2-digit",
            day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(new Date(checkedAt))}
        </time>
      </p>}
      {children}
    </section>
  );
}
