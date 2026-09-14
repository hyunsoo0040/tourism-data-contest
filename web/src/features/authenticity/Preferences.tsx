import type { Axis, Facet } from "./api";
import styles from "./Journey.module.css";
import {facilityLabels,type Facility,type Options} from "./preferenceState";
export {afterImportance,emptyOptions,photoConflict,restoreOptions} from "./preferenceState";

export function PreferenceControls({facet,label,importance,options,onChange,onAvoid}: {
  facet:Facet;label:string;importance:number|null|undefined;options:Options;
  onChange:(options:Options)=>void;onAvoid:(strength:number)=>void;
}){
  return <details className={styles.preference}>
    <summary>{label}의 강도·피하기 조정{options.avoid[facet]?" · 피하기 설정됨":options.desired[facet]!==undefined?" · 강도 설정됨":" (선택)"}</summary>
    <p className={styles.small}>위 응답은 이번 여행에서의 중요도예요. 원하는 강도가 따로 있거나 이 경험을 피하고 싶다면 조정해 주세요.</p>
    <div className={styles.preferenceGrid}>
      <label className={styles.control}>{label} 원하는 강도
        <select aria-label={`${label} 원하는 강도`} value={options.desired[facet]??""} disabled={(importance??0)===0} onChange={e=>{
          const desired={...options.desired};if(e.target.value==="")delete desired[facet];else desired[facet]=Number(e.target.value);
          onChange({...options,desired});
        }}>
          <option value="">별도 강도 없이 기대 충족 우선</option>
          {["아주 약하게","약하게","보통","뚜렷하게","아주 뚜렷하게"].map((s,i)=><option key={s} value={i}>{s}</option>)}
        </select>
      </label>
      <label className={styles.control}>{label} 피하기
        <select aria-label={`${label} 피하기`} value={options.avoid[facet]??0} onChange={e=>onAvoid(Number(e.target.value))}>
          {["피하기 조건 없음","가급적 낮게","어느 정도 피하기","중요하게 피하기","꼭 피하기"].map((s,i)=><option key={s} value={i}>{s}</option>)}
        </select>
      </label>
    </div>
    {(importance??0)===0&&!options.avoid[facet]&&<p className={styles.small}>원하는 강도는 중요도를 선택한 뒤 조정할 수 있어요.</p>}
    {!!options.avoid[facet]&&<p className={styles.small}>이 항목은 피할 경험으로 반영해요. 위 중요도는 ‘상관없어요’로 전환했습니다.</p>}
  </details>;
}

export function FacilityControls({options,onChange}:{options:Options;onChange:(options:Options)=>void}){
  return <details className={styles.preference}><summary>꼭 필요한 시설 (선택)</summary>
    <p className={styles.small}>선택한 시설이 공식 자료로 확인되는 장소만 추천해요. 자료가 없으면 추천 수가 줄어들 수 있어요.</p>
    <div className={styles.facilities}>{Object.entries(facilityLabels).map(([key,label])=><label key={key}>
      <input type="checkbox" checked={options.facilities.includes(key as Facility)} onChange={e=>onChange({...options,facilities:e.target.checked?[...options.facilities,key as Facility]:options.facilities.filter(k=>k!==key)})}/>{label}
    </label>)}</div>
  </details>;
}

export type PersonalRatings = Partial<Record<Axis,number|null>>;
export function PersonalExperienceControls({ratings,onChange,disabled}:{ratings:PersonalRatings;onChange:(ratings:PersonalRatings)=>void;disabled:boolean}){
  return <div className={styles.preferenceGrid}>{([["H","대상•원형형"],["E","의미•이미지형"],["R","자기•몰입형"]] as const).map(([axis,label])=><label className={styles.control} key={axis}>{label} 기대 충족
    <select aria-label={`${label} 기대 충족`} disabled={disabled} value={ratings[axis]??""} onChange={e=>onChange({...ratings,[axis]:e.target.value===""?null:Number(e.target.value)})}>
      <option value="">이 경험은 평가하지 않음</option>
      {["전혀 충족하지 못했어요","조금 충족했어요","어느 정도 충족했어요","많이 충족했어요","충분히 충족했어요"].map((s,i)=><option value={i} key={s}>{s}</option>)}
    </select>
  </label>)}</div>;
}
