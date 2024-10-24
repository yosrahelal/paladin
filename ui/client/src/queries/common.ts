export const generatePostReq = (stringBody: string): RequestInit => {
  return {
    body: stringBody,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    method: "POST",
  };
};

export const returnResponse = async (
  res: Response,
  errorMsg: string,
  ignoreStatuses: number[] = []
) => {
  if (!res.ok && !ignoreStatuses.includes(res.status)) {
    throw new Error(errorMsg);
  }
  try {
    return (await res.json()).result;
  } catch {
    return {};
  }
};
