// Licensed to Cloudera, Inc. under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  Cloudera, Inc. licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiFetchOptions, get } from '../../../api/utils';
import { AxiosError } from 'axios';
import { convertKeysToCamelCase } from '../../../utils/string/changeCasing';

export interface Options<T, U> {
  params?: U;
  fetchOptions?: ApiFetchOptions<T>;
  skip?: boolean;
  onSuccess?: (data: T) => void;
  onError?: (error: AxiosError) => void;
  pollInterval?: number;
  transformKeys?: 'camelCase' | 'none';
}

interface UseLoadDataProps<T> {
  data?: T;
  loading: boolean;
  error?: AxiosError;
  reloadData: () => Promise<T | undefined>;
}

const useLoadData = <T, U = unknown>(
  url?: string,
  options?: Options<T, U>
): UseLoadDataProps<T> => {
  const [localOptions, setLocalOptions] = useState<Options<T, U> | undefined>(options);
  const [data, setData] = useState<T>();
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<AxiosError>();

  const fetchOptionsDefault: ApiFetchOptions<T> = {
    silenceErrors: true,
    ignoreSuccessErrors: true,
    isRawError: true
  };

  const fetchOptions = useMemo(
    () => ({ ...fetchOptionsDefault, ...localOptions?.fetchOptions }),
    [localOptions]
  );

  const transformResponse = (data: T): T => {
    if (options?.transformKeys === 'none') {
      return data;
    }

    if (data && (options?.transformKeys === undefined || options?.transformKeys === 'camelCase')) {
      return convertKeysToCamelCase<T>(data);
    }

    return data;
  };

  const loadData = useCallback(
    async (isForced: boolean = false) => {
      // Avoid fetching data if the skip option is true
      // or if the URL is not provided
      if ((options?.skip && !isForced) || !url) {
        return;
      }
      setLoading(true);
      setError(undefined);

      try {
        const response = await get<T, U>(url, localOptions?.params, fetchOptions);
        const transformedResponse = transformResponse(response);
        setData(transformedResponse);
        if (localOptions?.onSuccess) {
          localOptions.onSuccess(transformedResponse);
        }
        return transformedResponse;
      } catch (error) {
        setError(error as AxiosError);
        if (localOptions?.onError) {
          localOptions.onError(error as AxiosError);
        }
      } finally {
        setLoading(false);
      }
    },
    [url, localOptions, fetchOptions]
  );

  useEffect(() => {
    let interval: NodeJS.Timeout | undefined;

    if (localOptions?.pollInterval) {
      interval = setInterval(() => {
        loadData();
      }, localOptions.pollInterval);
    }

    // Cleanup interval if pollInterval is undefined or when the component unmounts
    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [localOptions?.pollInterval, loadData]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    // set new options if they are different (deep comparison)
    if (JSON.stringify(options) !== JSON.stringify(localOptions)) {
      setLocalOptions(options);
    }
  }, [options]);

  return { data, loading, error, reloadData: () => loadData(true) };
};

export default useLoadData;
