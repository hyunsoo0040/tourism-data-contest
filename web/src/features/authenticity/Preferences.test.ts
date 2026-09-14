import {describe,it,expect} from "vitest";
import {afterImportance,photoConflict,restoreOptions} from "./preferenceState";

describe("explicit expectation options",()=>{
  it("restores only typed compatible options and known facility keys",()=>{
    expect(restoreOptions({desired:{"H.a":0,"H.b":2,"invalid":4},avoid:{"H.a":4,"H.b":2},facilities:["accessible_toilet","accessible_toilet","invented"]},{"H.a":4,"H.b":0})).toEqual({desired:{"H.a":0},avoid:{"H.b":2},facilities:["accessible_toilet"]});
  });
  it("seeking and avoiding cannot silently coexist and photo conflicts are explicit",()=>{
    const options={desired:{"H.a":0},avoid:{"H.b":3},facilities:[]};
    expect(afterImportance(options,"H.b",2).avoid).toEqual({});
    expect(afterImportance(options,"H.b",null).avoid).toEqual({});
    expect(afterImportance(options,"H.b",0).avoid).toEqual({});
    expect(afterImportance(options,"H.a",0).desired).toEqual({});
    expect(photoConflict(["greenery"],{"R.b":2})).toBe(true);
    expect(photoConflict(["traditional_appearance"],{"H.a":2})).toBe(false);
  });
});
