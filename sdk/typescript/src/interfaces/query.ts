export interface IQueryOp {
  not?: boolean;
  caseInsensitive?: boolean;
  field: string;
}

export interface IQueryOpSingleVal extends IQueryOp {
  value: any;
}

export interface IQueryOpMultiVal extends IQueryOp {
  values: any[];
}

export interface IQueryStatements {
  or?: IQueryStatements[];
  equal?: IQueryOpSingleVal[];
  eq?: IQueryOpSingleVal[];
  neq?: IQueryOpSingleVal[];
  like?: IQueryOpSingleVal[];
  lessThan?: IQueryOpSingleVal[];
  lt?: IQueryOpSingleVal[];
  lessThanOrEqual?: IQueryOpSingleVal[];
  lte?: IQueryOpSingleVal[];
  greaterThan?: IQueryOpSingleVal[];
  gt?: IQueryOpSingleVal[];
  greaterThanOrEqual?: IQueryOpSingleVal[];
  gte?: IQueryOpSingleVal[];
  in?: IQueryOpMultiVal[];
  nin?: IQueryOpMultiVal[];
  null?: IQueryOp;
}

export interface IQuery extends IQueryStatements {
  limit?: number;
  sort?: string[];
}
