import type { Facet, Submission } from "./api";
export type Facility = NonNullable<Submission["requirements"]>["required_facilities"] extends (infer T)[] | undefined ? T : never;
export const facilityLabels: Record<Facility,string> = {
  wheelchair_rental:"휠체어 대여", stroller_rental:"유모차 대여", accessible_toilet:"장애인 화장실",
  accessible_parking:"장애인 주차구역", step_free_entry:"계단 없는 출입",
};
export type Options = { desired: Partial<Record<Facet,number>>; avoid: Partial<Record<Facet,number>>; facilities: Facility[] };
export const emptyOptions = ():Options => ({desired:{},avoid:{},facilities:[]});
const record = (value:unknown):Record<string,unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string,unknown> : {};

export function restoreOptions(raw:unknown, answers:Partial<Record<Facet,number|null>>):Options {
  const value=record(raw), desired:Options["desired"]={}, avoid:Options["avoid"]={};
  for(const [key,v] of Object.entries(record(value.desired))){
    if(Object.hasOwn(answers,key)&&Number.isInteger(v)&&Number(v)>=0&&Number(v)<=4&&(answers[key as Facet]??0)>0)desired[key as Facet]=Number(v);
  }
  for(const [key,v] of Object.entries(record(value.avoid))){
    if(Object.hasOwn(answers,key)&&Number.isInteger(v)&&Number(v)>0&&Number(v)<=4&&(answers[key as Facet]??0)===0)avoid[key as Facet]=Number(v);
  }
  const facilities=Array.isArray(value.facilities)?[...new Set(value.facilities.filter((x):x is Facility=>typeof x==="string"&&Object.hasOwn(facilityLabels,x)))]:[];
  return {desired,avoid,facilities};
}

export function afterImportance(options:Options,key:Facet,value:number|null):Options {
  const desired={...options.desired},avoid={...options.avoid};
  delete avoid[key];
  if((value??0)===0)delete desired[key];
  return {...options,desired,avoid};
}

export function photoConflict(dimensions:string[],avoid:Options["avoid"]):boolean {
  return dimensions.some(d=>(avoid[(["greenery","water","open_composition"].includes(d)?"R.b":"E.c")]??0)>0);
}
